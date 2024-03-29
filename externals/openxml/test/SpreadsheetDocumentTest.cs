﻿using System;
using System.IO;

using Xunit;

using Zongsoft.Externals.OpenXml;
using Zongsoft.Externals.OpenXml.Spreadsheet;

namespace Zongsoft.Externals.OpenXml.Tests
{
	public class SpreadsheetDocumentTest
	{
		[Fact]
		public void TestCreateDocumentViaFile()
		{
			var filePath = Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\files\", "temp.xlsx");
			var document = SpreadsheetDocument.Create(filePath);

			Assert.NotNull(document);
			Assert.NotNull(document.Sheets);
			Assert.Single(document.Sheets);
			Assert.Equal("Sheet1", document.Sheets[0].Name);

			document.Sheets.Add("MySheet");
			Assert.Equal(2, document.Sheets.Count);
			Assert.Equal("MySheet", document.Sheets[1].Name);

			//测试单元格的数据读写
			TestCells(document);

			document.Save();
			document.Dispose();

			if(File.Exists(filePath))
				File.Delete(filePath);
		}

		[Fact]
		public void TestCreateDocumentViaStream()
		{
			using var memory = new MemoryStream();
			using var document = SpreadsheetDocument.Create(memory);

			Assert.NotNull(document);
			Assert.NotNull(document.Sheets);
			Assert.Single(document.Sheets);
			Assert.Equal("Sheet1", document.Sheets[0].Name);

			document.Sheets.Add("MySheet");
			Assert.Equal(2, document.Sheets.Count);
			Assert.Equal("MySheet", document.Sheets[1].Name);

			//测试单元格的数据读写
			TestCells(document);
		}

		private void TestCells(SpreadsheetDocument document)
		{
			document.Sheets[0].Cells.SetValue("A1", "A1-Value");
			Assert.Equal("A1-Value", document.Sheets[0].Cells.GetText("A1"));

			document.Sheets[0].Cells.SetValue("A2", "A2-Value");
			Assert.Equal("A2-Value", document.Sheets[0].Cells.GetText("A2"));
			Assert.True(document.Sheets[0].Cells.TryGetValue("A2", out string text));
			Assert.Equal("A2-Value", text);

			document.Sheets[0].Cells.SetValue("A3", 100.5m);
			Assert.Equal("100.5", document.Sheets[0].Cells.GetText("A3"));
			Assert.True(document.Sheets[0].Cells.TryGetValue("A3", out decimal @decimal));
			Assert.Equal(100.5m, @decimal);

			document.Sheets[0].Cells.SetValue("A4", 300.15);
			Assert.Equal("300.15", document.Sheets[0].Cells.GetText("A4"));
			Assert.True(document.Sheets[0].Cells.TryGetValue("A4", out double @double));
			Assert.Equal(300.15, @double);

			document.Sheets[0].Cells.SetValue("A5", 500);
			Assert.Equal("500", document.Sheets[0].Cells.GetText("A5"));
			Assert.True(document.Sheets[0].Cells.TryGetValue("A5", out int @integer));
			Assert.Equal(500, @integer);

			document.Sheets[0].Cells.SetValue("A6", true);
			Assert.True(bool.Parse(document.Sheets[0].Cells.GetText("A6")));
			Assert.True(document.Sheets[0].Cells.TryGetValue("A6", out bool @true));
			Assert.True(@true);

			document.Sheets[0].Cells.SetValue("A7", false);
			Assert.False(bool.Parse(document.Sheets[0].Cells.GetText("A7")));
			Assert.True(document.Sheets[0].Cells.TryGetValue("A7", out bool @false));
			Assert.False(@false);

			document.Sheets[0].Cells.SetValue("B9", "B9-Value");
			Assert.Equal("B9-Value", document.Sheets[0].Cells.GetText("B9"));

			document.Sheets[0].Cells.SetValue("B1", "B1-Value");
			Assert.Equal("B1-Value", document.Sheets[0].Cells.GetText("B1"));

			document.Sheets[0].Cells.Merge("A1:B1");
			document.Sheets[0].Cells.Unmerge("A1:B1");
		}
	}
}
