// Hosted coverage for kernel/fs/fat32_write_bounds.h.
//
// FAT32 directory entries store file size in 32 bits. These checks pin the
// fail-closed arithmetic used before any cluster allocation or data write.

#include "fs/fat32_write_bounds.h"
#include "host_test_helper.h"

using duetos::u64;
using duetos::fs::fat32::internal::CheckedWriteEnd;
using duetos::fs::fat32::internal::kFat32MaxFileSize;

int main()
{
    u64 end = 0;

    EXPECT_TRUE(CheckedWriteEnd(8, 9, 17, &end));
    EXPECT_EQ(end, 17ull);

    EXPECT_TRUE(CheckedWriteEnd(kFat32MaxFileSize, 0, kFat32MaxFileSize, &end));
    EXPECT_EQ(end, kFat32MaxFileSize);

    EXPECT_FALSE(CheckedWriteEnd(kFat32MaxFileSize, 1, kFat32MaxFileSize, &end));
    EXPECT_FALSE(CheckedWriteEnd(8, ~u64{0} - 7, 17, &end));
    EXPECT_FALSE(CheckedWriteEnd(18, 0, 17, &end));
    EXPECT_FALSE(CheckedWriteEnd(0, 1, 1, nullptr));

    return duetos_host_test::finish_main("fat32_write_bounds");
}
