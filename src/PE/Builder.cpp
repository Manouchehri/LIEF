/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <algorithm>
#include <fstream>
#include <iterator>

#include "easylogging++.h"

#include "LIEF/utf8.h"
#include "LIEF/exception.hpp"

#include "LIEF/PE/Builder.hpp"
#include "Builder.tcc"
#include "LIEF/PE/ResourceData.hpp"
#include "LIEF/PE/utils.hpp"



namespace LIEF {
namespace PE {

Builder::~Builder(void) = default;

Builder::Builder(Binary* binary) :
  binary_{binary},
  build_imports_{false},
  patch_imports_{false},
  build_relocations_{false},
  build_tls_{false},
  build_resources_{false}
{}


Builder& Builder::build_imports(bool flag) {
  this->build_imports_ = flag;
  return *this;
}
Builder& Builder::patch_imports(bool flag) {
  this->patch_imports_ = flag;
  return *this;
}

Builder& Builder::build_relocations(bool flag) {
  this->build_relocations_ = flag;
  return *this;
}

Builder& Builder::build_tls(bool flag) {
  this->build_tls_ = flag;
  return *this;
}

Builder& Builder::build_resources(bool flag) {
  this->build_resources_ = flag;
  return *this;
}




void Builder::write(const std::string& filename) const {
  std::ofstream output_file{filename, std::ios::out | std::ios::binary | std::ios::trunc};
  if (output_file) {
    std::vector<uint8_t> content;
    this->ios_.get(content);
    std::copy(
        std::begin(content),
        std::end(content),
        std::ostreambuf_iterator<char>(output_file));
  }
}




void Builder::build(void) {

  LOG(DEBUG) << "Rebuilding" << std::endl;

  if (this->binary_->has_tls() and this->build_tls_) {
    LOG(DEBUG) << "[+] Rebuilding TLS" << std::endl;
    if (this->binary_->type() == PE_TYPE::PE32) {
      this->build_tls<PE32>();
    } else {
      this->build_tls<PE64>();
    }
  }

  if (this->binary_->has_relocations() and this->build_relocations_) {
    LOG(DEBUG) << "[+] Rebuilding relocations" << std::endl;
    this->build_relocation();
  }

  if (this->binary_->has_resources() and this->binary_->resources_ != nullptr and this->build_resources_) {
    LOG(DEBUG) << "[+] Rebuilding resources" << std::endl;
    try {
      this->build_resources();
    } catch (not_found&) {
    }
  }

  if (this->binary_->has_imports() and this->build_imports_) {
    LOG(DEBUG) << "[+] Rebuilding Import" << std::endl;
    if (this->binary_->type() == PE_TYPE::PE32) {
      this->build_import_table<PE32>();
    } else {
      this->build_import_table<PE64>();
    }
  }

  LOG(DEBUG) << "[+] Rebuilding headers" << std::endl;

  *this << this->binary_->dos_header()
        << this->binary_->header()
        << this->binary_->optional_header();

  for (const DataDirectory& directory : this->binary_->data_directories()) {
    *this << directory;
  }

  DataDirectory last_one;
  last_one.RVA(0);
  last_one.size(0);

  *this << last_one;

  LOG(DEBUG) << "[+] Rebuilding sections" << std::endl;

  for (const Section& section : this->binary_->get_sections()) {
    LOG(DEBUG) << "Building section " << section.name();
    *this << section;
  }

  LOG(DEBUG) << "[+] Rebuilding symbols" << std::endl;
  //this->build_symbols();


  LOG(DEBUG) << "[+] Rebuilding string table" << std::endl;
  //this->build_string_table();
}

const std::vector<uint8_t>& Builder::get_build(void) {
  return this->ios_.raw();
}

//
// Build relocations
//
void Builder::build_relocation(void) {
  std::vector<uint8_t> content;
  for (const Relocation& relocation : this->binary_->relocations()) {

    pe_base_relocation_block relocation_header;
    relocation_header.PageRVA   = static_cast<uint32_t>(relocation.virtual_address());

    uint32_t block_size = static_cast<uint32_t>((relocation.entries().size()) * sizeof(uint16_t) + sizeof(pe_base_relocation_block));
    relocation_header.BlockSize = align(block_size, sizeof(uint32_t));

    content.insert(
        std::end(content),
        reinterpret_cast<uint8_t*>(&relocation_header),
        reinterpret_cast<uint8_t*>(&relocation_header) + sizeof(pe_base_relocation_block));

    for (const RelocationEntry& entry: relocation.entries()) {
      uint16_t data = entry.data();
      content.insert(
          std::end(content),
          reinterpret_cast<uint8_t*>(&data),
          reinterpret_cast<uint8_t*>(&data) + sizeof(uint16_t));
    }

    content.insert(
      std::end(content),
      align(content.size(), sizeof(uint32_t)) - content.size(), 0);
  }

  // Align on a 32 bits

  //pe_base_relocation_block relocHeader;
  //relocHeader.PageRVA   = static_cast<uint32_t>(0);
  //relocHeader.BlockSize = static_cast<uint32_t>(0);

  //content.insert(
  //    std::end(content),
  //    reinterpret_cast<uint8_t*>(&relocHeader),
  //    reinterpret_cast<uint8_t*>(&relocHeader) + sizeof(pe_base_relocation_block));

  Section new_relocation_section{".l" + std::to_string(DATA_DIRECTORY::BASE_RELOCATION_TABLE)}; // .l5 -> lief.relocation
  new_relocation_section.characteristics(0x42000040);
  const size_t size_aligned = align(content.size(), this->binary_->optional_header().file_alignment());

  // Pad with 0
  content.insert(
      std::end(content),
      size_aligned - content.size(), 0);

  new_relocation_section.content(content);

  this->binary_->add_section(new_relocation_section, SECTION_TYPES::RELOCATION);
}


//
// Build resources
//
void Builder::build_resources(void) {
  LOG(DEBUG) << "Building RSRC" << std::endl;

  ResourceNode* node = this->binary_->resources_;

  uint32_t headerSize = 0;
  uint32_t dataSize   = 0;
  uint32_t nameSize   = 0;

  this->compute_resources_size(node, &headerSize, &dataSize, &nameSize);
  std::vector<uint8_t> content(headerSize + dataSize + nameSize, 0);
  const uint64_t content_size_aligned = align(content.size(), this->binary_->optional_header().file_alignment());
  content.insert(std::end(content), content_size_aligned - content.size(), 0);

  uint32_t offsetToHeader = 0;
  uint32_t offsetToName   = headerSize;
  uint32_t offsetToData   = headerSize + nameSize;

  Section new_section_rsrc{".l" + std::to_string(DATA_DIRECTORY::RESOURCE_TABLE)};
  new_section_rsrc.characteristics(0x40000040);
  new_section_rsrc.content(content);

  Section& rsrc_section = this->binary_->add_section(new_section_rsrc, SECTION_TYPES::RESOURCE);

  this->construct_resources(node, &content, &offsetToHeader, &offsetToData, &offsetToName, rsrc_section.virtual_address(), 0);

  rsrc_section.content(content);
}

//
// Pre-computation
//
void Builder::compute_resources_size(ResourceNode *node, uint32_t *headerSize, uint32_t *dataSize, uint32_t *nameSize) {
  if (not node->name().empty()) {
    *nameSize += sizeof(uint16_t) + node->name().size() * sizeof(char16_t) + 1;
  }

  if (node->type() == RESOURCE_NODE_TYPES::DIRECTORY) {
    *headerSize += STRUCT_SIZES::ResourceDirectoryTableSize;
    *headerSize += STRUCT_SIZES::ResourceDirectoryEntriesSize;
  } else {
    ResourceData *dataNode = static_cast<ResourceData*>(node);
    *headerSize += STRUCT_SIZES::ResourceDataEntrySize;
    *headerSize += STRUCT_SIZES::ResourceDirectoryEntriesSize;
    *dataSize   += dataNode->content_.size() + 1;
  }

  for (auto& child : node->childs()) {
    this->compute_resources_size(child, headerSize, dataSize, nameSize);
  }
}


//
// Build level by level
//
void Builder::construct_resources(
    ResourceNode *node,
    std::vector<uint8_t> *content,
    uint32_t *offsetToHeader,
    uint32_t *offsetToData,
    uint32_t *offsetToName,
    uint32_t baseRVA,
    uint32_t depth) {

  // Build Directory
  // ===============

  if (node->type() == RESOURCE_NODE_TYPES::DIRECTORY) {
    //LOG(DEBUG) << "Build level " << std::dec << depth << std::endl;
    ResourceDirectory *rsrcDirectory = static_cast<ResourceDirectory*>(node);

    pe_resource_directory_table rsrcHeader;
    rsrcHeader.Characteristics     = static_cast<uint32_t>(rsrcDirectory->characteristics_);
    rsrcHeader.TimeDateStamp       = static_cast<uint32_t>(rsrcDirectory->timeDateStamp_);
    rsrcHeader.MajorVersion        = static_cast<uint16_t>(rsrcDirectory->majorVersion_);
    rsrcHeader.MinorVersion        = static_cast<uint16_t>(rsrcDirectory->minorVersion_);
    rsrcHeader.NumberOfNameEntries = static_cast<uint16_t>(rsrcDirectory->numberOfNameEntries_);
    rsrcHeader.NumberOfIDEntries   = static_cast<uint16_t>(rsrcDirectory->numberOfIDEntries_);


    std::copy(
        reinterpret_cast<uint8_t*>(&rsrcHeader),
        reinterpret_cast<uint8_t*>(&rsrcHeader) + STRUCT_SIZES::ResourceDirectoryTableSize,
        content->data() + *offsetToHeader);

    *offsetToHeader += STRUCT_SIZES::ResourceDirectoryTableSize;

    //Build next level
    uint32_t currentOffset = *offsetToHeader;

    // Offset to the next RESOURCE_NODE_TYPES::DIRECTORY
    *offsetToHeader += node->childs().size() * STRUCT_SIZES::ResourceDirectoryEntriesSize;


    // Build childs
    // ============
    for (ResourceNode* child : node->childs()) {
      if (static_cast<uint32_t>(child->id_) & 0x80000000) { // There is a name


        const std::u16string& name = child->name();
        child->id_ = 0x80000000 | *offsetToName;

        //for (uint32_t i = 0; i < name.size(); ++i) {
        //  std::cout << static_cast<char>(name.data()[i]);
        //}
        //std::cout << std::endl;

        uint16_t* length_ptr = reinterpret_cast<uint16_t*>(content->data() + *offsetToName);
        *length_ptr = name.size();
        char16_t* name_ptr = reinterpret_cast<char16_t*>(content->data() + *offsetToName + sizeof(uint16_t));

        std::copy(
            reinterpret_cast<const char16_t*>(name.data()),
            reinterpret_cast<const char16_t*>(name.data()) + name.size(),
            name_ptr);

        *offsetToName += name.size() * sizeof(char16_t) + sizeof(uint16_t) + 1;
      }

      if (child->type() == RESOURCE_NODE_TYPES::DIRECTORY) {

        pe_resource_directory_entries entryHeader;
        entryHeader.NameID.IntegerID = static_cast<uint32_t>(child->id());
        entryHeader.RVA              = static_cast<uint32_t>((0x80000000 | *offsetToHeader));

        std::copy(
            reinterpret_cast<uint8_t*>(&entryHeader),
            reinterpret_cast<uint8_t*>(&entryHeader) + STRUCT_SIZES::ResourceDirectoryEntriesSize,
            content->data() + currentOffset);

        currentOffset += STRUCT_SIZES::ResourceDirectoryEntriesSize;
        this->construct_resources(child, content, offsetToHeader, offsetToData, offsetToName, baseRVA, depth + 1);
      } else { //DATA
        pe_resource_directory_entries entryHeader;

        entryHeader.NameID.IntegerID = static_cast<uint32_t>(child->id());
        entryHeader.RVA              = static_cast<uint32_t>(*offsetToHeader);

        std::copy(
            reinterpret_cast<uint8_t*>(&entryHeader),
            reinterpret_cast<uint8_t*>(&entryHeader) + STRUCT_SIZES::ResourceDirectoryEntriesSize,
            content->data() + currentOffset);
        currentOffset += STRUCT_SIZES::ResourceDirectoryEntriesSize;
        this->construct_resources(child, content, offsetToHeader, offsetToData, offsetToName, baseRVA, depth + 1);
      }
    }

  } else {
    //LOG(DEBUG) << "Building Data" << std::endl;
    ResourceData *rsrcData = static_cast<ResourceData*>(node);
    pe_resource_data_entry dataHeader;
    dataHeader.DataRVA  = static_cast<uint32_t>(baseRVA + *offsetToData);
    dataHeader.Size     = static_cast<uint32_t>(rsrcData->content_.size());
    dataHeader.Codepage = static_cast<uint32_t>(rsrcData->codePage_);
    dataHeader.Reserved = static_cast<uint32_t>(0);


    std::copy(
        reinterpret_cast<uint8_t*>(&dataHeader),
        reinterpret_cast<uint8_t*>(&dataHeader) + STRUCT_SIZES::ResourceDataEntrySize,
        content->data() + *offsetToHeader);

    *offsetToHeader += STRUCT_SIZES::ResourceDirectoryTableSize;

    std::copy(
        std::begin(rsrcData->content_),
        std::end(rsrcData->content_),
        content->data() + *offsetToData);

    *offsetToData += rsrcData->content().size() + 1;
  }
}


void Builder::build_symbols(void) {
  //TODO
}


void Builder::build_string_table(void) {
  //TODO
}

Builder& Builder::operator<<(const DosHeader& dos_header) {

  pe_dos_header dosHeader;
  dosHeader.Magic                     = static_cast<uint16_t>(dos_header.magic());
  dosHeader.UsedBytesInTheLastPage    = static_cast<uint16_t>(dos_header.used_bytes_in_the_last_page());
  dosHeader.FileSizeInPages           = static_cast<uint16_t>(dos_header.file_size_in_pages());
  dosHeader.NumberOfRelocationItems   = static_cast<uint16_t>(dos_header.numberof_relocation());
  dosHeader.HeaderSizeInParagraphs    = static_cast<uint16_t>(dos_header.header_size_in_paragraphs());
  dosHeader.MinimumExtraParagraphs    = static_cast<uint16_t>(dos_header.minimum_extra_paragraphs());
  dosHeader.MaximumExtraParagraphs    = static_cast<uint16_t>(dos_header.maximum_extra_paragraphs());
  dosHeader.InitialRelativeSS         = static_cast<uint16_t>(dos_header.initial_relative_ss());
  dosHeader.InitialSP                 = static_cast<uint16_t>(dos_header.initial_sp());
  dosHeader.Checksum                  = static_cast<uint16_t>(dos_header.checksum());
  dosHeader.InitialIP                 = static_cast<uint16_t>(dos_header.initial_ip());
  dosHeader.InitialRelativeCS         = static_cast<uint16_t>(dos_header.initial_relative_cs());
  dosHeader.AddressOfRelocationTable  = static_cast<uint16_t>(dos_header.addressof_relocation_table());
  dosHeader.OverlayNumber             = static_cast<uint16_t>(dos_header.overlay_number());
  dosHeader.OEMid                     = static_cast<uint16_t>(dos_header.oem_id());
  dosHeader.OEMinfo                   = static_cast<uint16_t>(dos_header.oem_info());
  dosHeader.AddressOfNewExeHeader     = static_cast<uint16_t>(dos_header.addressof_new_exeheader());

  const DosHeader::reserved_t& reserved   = dos_header.reserved();
  const DosHeader::reserved2_t& reserved2 = dos_header.reserved2();

  std::copy(std::begin(reserved),  std::end(reserved),  std::begin(dosHeader.Reserved));
  std::copy(std::begin(reserved2), std::end(reserved2), std::begin(dosHeader.Reserved2));

  this->ios_.seekp(0);
  this->ios_.write(reinterpret_cast<const uint8_t*>(&dosHeader), sizeof(pe_dos_header));
  return *this;
}


Builder& Builder::operator<<(const Header& bHeader) {
  LOG(DEBUG) << "Building standard Header" << std::endl;
  // Standard Header
  pe_header header;
  header.Machine               = static_cast<uint16_t>(bHeader.machine());
  header.NumberOfSections      = static_cast<uint16_t>(this->binary_->sections_.size());
  //TODO: use current
  header.TimeDateStamp         = static_cast<uint32_t>(bHeader.time_date_stamp());
  header.PointerToSymbolTable  = static_cast<uint32_t>(bHeader.pointerto_symbol_table());
  header.NumberOfSymbols       = static_cast<uint32_t>(bHeader.numberof_symbols());
  //TODO: Check
  header.SizeOfOptionalHeader  = static_cast<uint16_t>(bHeader.sizeof_optional_header());
  header.Characteristics       = static_cast<uint16_t>(bHeader.characteristics());

  const Header::signature_t& signature = this->binary_->header_.signature();
  std::copy(std::begin(signature), std::end(signature), std::begin(header.signature));

  const uint32_t address_next_header = this->binary_->dos_header().addressof_new_exeheader();

  this->ios_.seekp(address_next_header);
  this->ios_.write(reinterpret_cast<const uint8_t*>(&header), sizeof(pe_header));
  return *this;
}


Builder& Builder::operator<<(const OptionalHeader& optional_header) {
  if (this->binary_->type() == PE_TYPE::PE32) {
    this->build_optional_header<PE32>(optional_header);
  } else {
    this->build_optional_header<PE64>(optional_header);
  }
  return *this;
}


Builder& Builder::operator<<(const DataDirectory& data_directory) {

  pe_data_directory header;

  header.RelativeVirtualAddress = data_directory.RVA();
  header.Size                   = data_directory.size();

  this->ios_.write(reinterpret_cast<uint8_t*>(&header), sizeof(pe_data_directory));
  return *this;
}


Builder& Builder::operator<<(const Section& section) {

  pe_section header;
  header.VirtualAddress       = static_cast<uint32_t>(section.virtual_address());
  header.VirtualSize          = static_cast<uint32_t>(section.virtual_size());
  header.SizeOfRawData        = static_cast<uint32_t>(section.size());
  header.PointerToRawData     = static_cast<uint32_t>(section.pointerto_raw_data());
  header.PointerToRelocations = static_cast<uint32_t>(section.pointerto_relocation());
  header.PointerToLineNumbers = static_cast<uint32_t>(section.pointerto_line_numbers());
  header.NumberOfRelocations  = static_cast<uint16_t>(section.numberof_relocations());
  header.NumberOfLineNumbers  = static_cast<uint16_t>(section.numberof_line_numbers());
  header.Characteristics      = static_cast<uint32_t>(section.characteristics());
  const char* name            = section.name().c_str();

  std::copy(name, name + sizeof(header.Name), std::begin(header.Name));
  this->ios_.write(reinterpret_cast<uint8_t*>(&header), sizeof(pe_section));

  if (section.content().size() > section.size()) {
    LOG(WARNING) << section.name()
                 << " content size is bigger than section's header size"
                 << std::endl;
  }
  const size_t saved_offset = this->ios_.tellp();
  this->ios_.seekp(section.offset());
  this->ios_.write(section.content());
  this->ios_.seekp(saved_offset);
  return *this;
}

std::ostream& operator<<(std::ostream& os, const Builder& b) {
  os << std::left;
  os << std::boolalpha;
  os << std::setw(20) << "Builde imports:"     << b.build_imports_     << std::endl;
  os << std::setw(20) << "Patch imports:"      << b.patch_imports_     << std::endl;
  os << std::setw(20) << "Builde relocations:" << b.build_relocations_ << std::endl;
  os << std::setw(20) << "Builde TLS:"         << b.build_tls_         << std::endl;
  os << std::setw(20) << "Builder resources:"  << b.build_resources_   << std::endl;
  return os;
}


}
}