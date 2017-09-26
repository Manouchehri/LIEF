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
#include "pyPE.hpp"

#include "LIEF/visitors/Hash.hpp"
#include "LIEF/PE/LoadConfigurations.hpp"

#include <string>
#include <sstream>

template<class T>
using getter_t = T (LoadConfiguration::*)(void) const;

template<class T>
using setter_t = void (LoadConfiguration::*)(T);

void init_PE_LoadConfiguration_class(py::module& m) {
  py::class_<LoadConfiguration>(m, "LoadConfiguration")
    .def(py::init<>())

    .def_property_readonly("version",
        &LoadConfiguration::version,
        "")

    .def_property("characteristics",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::characteristics),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::characteristics),
        "")

    .def_property("timedatestamp",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::timedatestamp),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::timedatestamp),
        "")

    .def_property("major_version",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::major_version),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::major_version),
        "")

    .def_property("minor_version",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::minor_version),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::minor_version),
        "")

    .def_property("global_flags_clear",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::global_flags_clear),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::global_flags_clear),
        "")

    .def_property("global_flags_set",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::global_flags_set),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::global_flags_set),
        "")

    .def_property("critical_section_default_timeout",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::critical_section_default_timeout),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::critical_section_default_timeout),
        "")

    .def_property("decommit_free_block_threshold",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::decommit_free_block_threshold),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::decommit_free_block_threshold),
        "")

    .def_property("decommit_total_free_threshold",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::decommit_total_free_threshold),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::decommit_total_free_threshold),
        "")

    .def_property("lock_prefix_table",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::lock_prefix_table),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::lock_prefix_table),
        "")

    .def_property("maximum_allocation_size",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::maximum_allocation_size),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::maximum_allocation_size),
        "")

    .def_property("virtual_memory_threshold",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::virtual_memory_threshold),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::virtual_memory_threshold),
        "")

    .def_property("process_affinity_mask",
        static_cast<getter_t<uint64_t>>(&LoadConfiguration::process_affinity_mask),
        static_cast<setter_t<uint64_t>>(&LoadConfiguration::process_affinity_mask),
        "")

    .def_property("process_heap_flags",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::process_heap_flags),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::process_heap_flags),
        "")

    .def_property("csd_version",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::csd_version),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::csd_version),
        "")

    .def_property("reserved1",
        static_cast<getter_t<uint16_t>>(&LoadConfiguration::reserved1),
        static_cast<setter_t<uint16_t>>(&LoadConfiguration::reserved1),
        "")

    .def_property("editlist",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::editlist),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::editlist),
        "")

    .def_property("security_cookie",
        static_cast<getter_t<uint32_t>>(&LoadConfiguration::security_cookie),
        static_cast<setter_t<uint32_t>>(&LoadConfiguration::security_cookie),
        "")



    .def("__eq__", &LoadConfiguration::operator==)
    .def("__ne__", &LoadConfiguration::operator!=)
    .def("__hash__",
        [] (const LoadConfiguration& config) {
          return LIEF::Hash::hash(config);
        })


    .def("__str__", [] (const LoadConfiguration& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });


}
