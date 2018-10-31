cmake_minimum_required(VERSION 3.5)
PROJECT (FSS)

ADD_EXECUTABLE(fssgen fssgen.c utils.c block.c b64.c)
TARGET_COMPILE_OPTIONS(fssgen PUBLIC -maes)
TARGET_LINK_LIBRARIES(fssgen ssl crypto)

ADD_EXECUTABLE(fsseval fsseval.c utils.c block.c b64.c)
TARGET_COMPILE_OPTIONS(fsseval PUBLIC -maes)
TARGET_LINK_LIBRARIES(fsseval ssl crypto)
