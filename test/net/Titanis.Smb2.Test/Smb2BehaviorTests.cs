using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Titanis.Smb2.Test
{
	[TestClass]
	public class Smb2BehaviorTests
	{
		[TestMethod]
		public void DisconnectOverloads_RemainBackwardCompatible()
		{
			var disconnectServerLegacy = typeof(Smb2Client).GetMethod(
				nameof(Smb2Client.DisconnectServerAsync),
				new[] { typeof(string), typeof(int?) });
			var disconnectServerCurrent = typeof(Smb2Client).GetMethod(
				nameof(Smb2Client.DisconnectServerAsync),
				new[] { typeof(string), typeof(int?), typeof(bool) });
			var disconnectAllLegacy = typeof(Smb2Client).GetMethod(
				nameof(Smb2Client.DisconnectAllAsync),
				Type.EmptyTypes);
			var disconnectAllCurrent = typeof(Smb2Client).GetMethod(
				nameof(Smb2Client.DisconnectAllAsync),
				new[] { typeof(bool) });

			Assert.IsNotNull(disconnectServerLegacy, "Missing compatibility overload DisconnectServerAsync(string, int?).");
			Assert.IsNotNull(disconnectServerCurrent, "Missing current overload DisconnectServerAsync(string, int?, bool).");
			Assert.IsNotNull(disconnectAllLegacy, "Missing compatibility overload DisconnectAllAsync().");
			Assert.IsNotNull(disconnectAllCurrent, "Missing current overload DisconnectAllAsync(bool).");
		}

		[TestMethod]
		public void SeekOriginEnd_UsesFileLength()
		{
			const long expectedEof = 4096;
			var file = CreateUninitializedFile(expectedEof);

			var ctor = typeof(Smb2FileStream).GetConstructor(
				BindingFlags.Instance | BindingFlags.NonPublic,
				null,
				new[] { typeof(Smb2OpenFile), typeof(FileAccess), typeof(bool) },
				null);
			Assert.IsNotNull(ctor, "Could not find non-public Smb2FileStream constructor.");

			var stream = (Smb2FileStream)ctor.Invoke(new object[] { file, FileAccess.Write, false });

			long posAtEof = stream.Seek(0, SeekOrigin.End);
			Assert.AreEqual(expectedEof, posAtEof);
			Assert.AreEqual(expectedEof, stream.Position);

			long posFromEnd = stream.Seek(32, SeekOrigin.End);
			Assert.AreEqual(expectedEof - 32, posFromEnd);
			Assert.AreEqual(expectedEof - 32, stream.Position);
		}

		[TestMethod]
		public async Task CloseAsync_WhenAlreadyClosed_IsIdempotent()
		{
			const long expectedEof = 777;
			var file = CreateUninitializedFile(expectedEof);
			SetIsClosed(file, true);

			var attrs1 = await file.CloseAsync(Smb2CloseOptions.None, CancellationToken.None).ConfigureAwait(false);
			var attrs2 = await file.CloseAsync(Smb2CloseOptions.None, CancellationToken.None).ConfigureAwait(false);

			Assert.AreEqual(expectedEof, ReadEndOfFile(attrs1));
			Assert.AreEqual(expectedEof, ReadEndOfFile(attrs2));

			file.Dispose();
			await file.DisposeAsync().ConfigureAwait(false);
		}

		private static Smb2OpenFile CreateUninitializedFile(long endOfFile)
		{
			var file = (Smb2OpenFile)RuntimeHelpers.GetUninitializedObject(typeof(Smb2OpenFile));
			SetEndOfFile(file, endOfFile);
			return file;
		}

		private static void SetIsClosed(Smb2OpenFileObjectBase file, bool value)
		{
			var closedField = typeof(Smb2OpenFileObjectBase).GetField("<IsClosed>k__BackingField", BindingFlags.Instance | BindingFlags.NonPublic);
			Assert.IsNotNull(closedField, "Could not locate IsClosed backing field.");
			closedField.SetValue(file, value);
		}

		private static void SetEndOfFile(Smb2OpenFileObjectBase file, long endOfFile)
		{
			var infoField = typeof(Smb2OpenFileObjectBase).GetField("_info", BindingFlags.Instance | BindingFlags.NonPublic);
			Assert.IsNotNull(infoField, "Could not locate _info field.");

			object info = infoField.GetValue(file);
			Assert.IsNotNull(info, "Could not read _info.");

			var attrsField = info.GetType().GetField("attrs", BindingFlags.Instance | BindingFlags.NonPublic);
			Assert.IsNotNull(attrsField, "Could not locate attrs field.");

			object attrs = attrsField.GetValue(info);
			Assert.IsNotNull(attrs, "Could not read attrs.");

			var eofField = attrs.GetType().GetField("endOfFile", BindingFlags.Instance | BindingFlags.NonPublic);
			Assert.IsNotNull(eofField, "Could not locate endOfFile field.");
			eofField.SetValue(attrs, endOfFile);

			attrsField.SetValue(info, attrs);
			infoField.SetValue(file, info);
		}

		private static long ReadEndOfFile(Smb2OpenFileAttributes attrs)
		{
			object boxed = attrs;
			var eofField = boxed.GetType().GetField("endOfFile", BindingFlags.Instance | BindingFlags.NonPublic);
			Assert.IsNotNull(eofField, "Could not locate endOfFile field.");
			return (long)eofField.GetValue(boxed);
		}
	}
}
