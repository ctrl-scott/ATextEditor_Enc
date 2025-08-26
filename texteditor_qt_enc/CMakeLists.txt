# CMakeLists.txt
cmake_minimum_required(VERSION 3.26)
project(texteditor_qt_enc LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.5 COMPONENTS Widgets REQUIRED)
qt_standard_project_setup()

qt_add_executable(texteditor_qt
        src/main.cpp
        src/help.cpp          # <-- added
)

target_link_libraries(texteditor_qt PRIVATE Qt6::Widgets sodium)

set_target_properties(texteditor_qt PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_BUNDLE_NAME "A Text Editor"
)
