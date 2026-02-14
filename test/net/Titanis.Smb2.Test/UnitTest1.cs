using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using Titanis;

namespace Titanis.Smb2.Test
{
	[TestClass]
	public class UnitTest1
	{
		[TestMethod]
		public void TestUncPath_ServerName()
		{
			string path = @"\\server";

			var actual = UncPath.Parse(path);
			Assert.AreEqual(path, actual.ToString());
			Assert.AreEqual("server", actual.ServerName);
			Assert.AreEqual(string.Empty, actual.ShareName);
			Assert.AreEqual(string.Empty, actual.ShareRelativePath);
		}
		[TestMethod]
		public void TestUncPath_Invalid()
		{
			string path = @"server";

			_ = Assert.ThrowsExactly<ArgumentException>(() => UncPath.Parse(path));
		}
		[TestMethod]
		public void TestUncPath_ServerShareName()
		{
			string path = @"\\server\share";

			var actual = UncPath.Parse(path);
			Assert.AreEqual(path, actual.ToString());
			Assert.AreEqual("server", actual.ServerName);
			Assert.AreEqual("share", actual.ShareName);
			Assert.AreEqual(string.Empty, actual.ShareRelativePath);
		}
		[TestMethod]
		public void TestUncPath_ServerShareNamePath()
		{
			string path = @"\\server\share\path\file";

			var actual = UncPath.Parse(path);
			Assert.AreEqual(path, actual.ToString());
			Assert.AreEqual("server", actual.ServerName);
			Assert.AreEqual("share", actual.ShareName);
			Assert.AreEqual(@"path\file", actual.ShareRelativePath);
		}
		[TestMethod]
		public void TestUncPath_ServerShareNamePath_AltSeparator()
		{
			string path = @"//server/share/path/file";

			var actual = UncPath.Parse(path);
			Assert.AreEqual(@"\\server\share\path\file", actual.ToString());
			Assert.AreEqual("server", actual.ServerName);
			Assert.AreEqual("share", actual.ShareName);
			Assert.AreEqual(@"path\file", actual.ShareRelativePath);
		}
		[TestMethod]
		public void TestUncPath_ServerShareNamePath_MixedSeparator()
		{
			string path = @"//server\share/path\file";

			var actual = UncPath.Parse(path);
			Assert.AreEqual(@"\\server\share\path\file", actual.ToString());
			Assert.AreEqual("server", actual.ServerName);
			Assert.AreEqual("share", actual.ShareName);
			Assert.AreEqual(@"path\file", actual.ShareRelativePath);
		}
	}
}
