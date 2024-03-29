﻿using System;
using System.IO;
using System.Linq;

using Xunit;

namespace Zongsoft.IO.Tests
{
	public class FileSystemTest
	{
		[Fact]
		public void TestDirectory()
		{
			var text = @"zfs.local:/d/temp/sub-dir/[1]123.jpg";
			var path = Path.Parse(text);

			var directoryUrl = path.GetDirectoryUrl();

			//创建目录
			FileSystem.Directory.Create(directoryUrl);

			Assert.True(FileSystem.Directory.Exists(directoryUrl));
			Assert.True(FileSystem.Directory.Delete(directoryUrl));
		}

		[Fact]
		public void TestFiles()
		{
			const int FILE_COUNT = 10;

			if(!FileSystem.Directory.Exists("zfs.local:/d/temp/"))
				FileSystem.Directory.Create("zfs.local:/d/temp/");

			//生成一个随机的文件前缀名
			var prefix = string.Format("[{0:yyyyMMdd}]{1:N}", DateTime.Today, Guid.NewGuid());

			for(int i = 1; i <= FILE_COUNT; i++)
			{
				//创建临时文件
				using(var stream = FileSystem.File.Open(string.Format("zfs.local:/d/temp/{1}({0}).{2}", i, prefix, (i % 2 == 0 ? "log" : "txt")), FileMode.Create, FileAccess.Write))
				{
					using(var writer = new StreamWriter(stream))
					{
						writer.Write(i.ToString());
					}
				}
			}

			var count = 0;
			//使用正则匹配的方式查找文件
			var infos = LocalFileSystem.Instance.Directory.GetFiles(@"D:\temp", prefix + @"(/\d+/).log").ToArray();

			foreach(var info in infos)
			{
				Assert.StartsWith(prefix + "(", info.Name);
				Assert.EndsWith(").log", info.Name);

				count++;
			}

			Assert.True(count >= FILE_COUNT / 2);
			count = 0;

			//使用文件系统匹配的方式查找文件
			infos = LocalFileSystem.Instance.Directory.GetFiles(@"D:\temp", prefix + "*").ToArray();

			foreach(var info in infos)
			{
				Assert.StartsWith(prefix + "(", info.Name);
				Assert.True(info.Name.EndsWith(").log") || info.Name.EndsWith(").txt"));

				//删除临时文件
				LocalFileSystem.Instance.File.Delete(info.Path.Url);

				count++;
			}

			Assert.True(count == FILE_COUNT);
		}
	}
}
