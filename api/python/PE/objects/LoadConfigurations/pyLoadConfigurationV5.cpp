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
using getter_t = T (LoadConfigurationV5::*)(void) const;

template<class T>
using setter_t = void (LoadConfigurationV5::*)(T);

void init_PE_LoadConfigurationV5_class(py::module& m) {
  py::class_<LoadConfigurationV5, LoadConfigurationV4>(m, "LoadConfigurationV5")
    .def(py::init<>())

    .def_property("guard_rf_failure_routine",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV5::guard_rf_failure_routine),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV5::guard_rf_failure_routine),
        "")

    .def_property("guard_rf_failure_routine_function_pointer",
        static_cast<getter_t<uint64_t>>(&LoadConfigurationV5::guard_rf_failure_routine_function_pointer),
        static_cast<setter_t<uint64_t>>(&LoadConfigurationV5::guard_rf_failure_routine_function_pointer),
        "")

    .def_property("dynamic_value_reloctable_offset",
        static_cast<getter_t<uint32_t>>(&LoadConfigurationV5::dynamic_value_reloctable_offset),
        static_cast<setter_t<uint32_t>>(&LoadConfigurationV5::dynamic_value_reloctable_offset),
        "")

    .def_property("dynamic_value_reloctable_section",
        static_cast<getter_t<uint16_t>>(&LoadConfigurationV5::dynamic_value_reloctable_section),
        static_cast<setter_t<uint16_t>>(&LoadConfigurationV5::dynamic_value_reloctable_section),
        "")

    .def_property("reserved2",
        static_cast<getter_t<uint16_t>>(&LoadConfigurationV5::reserved2),
        static_cast<setter_t<uint16_t>>(&LoadConfigurationV5::reserved2),
        "")


    .def("__eq__", &LoadConfigurationV5::operator==)
    .def("__ne__", &LoadConfigurationV5::operator!=)
    .def("__hash__",
        [] (const LoadConfigurationV5& config) {
          return LIEF::Hash::hash(config);
        })


    .def("__str__", [] (const LoadConfigurationV5& config)
        {
          std::ostringstream stream;
          stream << config;
          std::string str = stream.str();
          return str;
        });


}
