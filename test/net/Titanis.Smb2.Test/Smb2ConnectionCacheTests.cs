#nullable enable
using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Titanis.Net;
using Titanis.Security;

namespace Titanis.Smb2.Test
{
	/// <summary>
	/// Regression tests for beads TBO-88r: <see cref="Smb2Client"/> must evict a half-built
	/// <see cref="Smb2Connection"/> from its internal connection cache when SESSION_SETUP or
	/// the re-auth loop fails. Prior to the fix, the cache retained the broken connection and
	/// subsequent callers would reuse it, producing WSAECONNRESET and (compounded with TBO-rom)
	/// credit-exhaustion failures.
	/// </summary>
	[TestClass]
	public class Smb2ConnectionCacheTests
	{
		/// <summary>
		/// Simulates the real-world TBO-88r repro:
		///   1. First call with no usable credentials — auth throws; eviction must fire.
		///   2. Second call (after creds are "fixed") — cache miss must force a fresh TCP connect.
		/// This test stays whitebox via reflection so it can pre-seed the cache without standing
		/// up a real SMB2 NEGOTIATE exchange.
		/// </summary>
		[TestMethod]
		public async Task OpenSessionAsync_AuthFailure_EvictsCachedConnection_AndRetryAttemptsFreshConnect()
		{
			const string serverName = "testserver.tbo88r.invalid";
			const int port = 445;

			var socketService = new CountingThrowingSocketService();
			var credService = new NullCredentialService();
			var client = new Smb2Client(credService, socketService);

			// Pre-seed the private _connections dictionary with a ConnectionGroup that holds an
			// uninitialized Smb2Connection. The eviction path is reached via OpenSessionAsync's
			// CreateAuthContext() throwing before conn0.AuthenticateAsync is called, so the
			// uninitialized connection is never touched for real network I/O.
			var connectionsField = typeof(Smb2Client).GetField("_connections", BindingFlags.Instance | BindingFlags.NonPublic);
			Assert.IsNotNull(connectionsField, "Could not locate Smb2Client._connections.");
			var connections = (IDictionary)connectionsField.GetValue(client)!;
			Assert.IsNotNull(connections, "Smb2Client._connections was null.");

			var keyType = typeof(Smb2Client).GetNestedType("ConnectionKey", BindingFlags.NonPublic);
			Assert.IsNotNull(keyType, "Could not locate nested type ConnectionKey.");
			var keyCtor = keyType!.GetConstructor(
				BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
				null,
				new[] { typeof(string), typeof(int) },
				null);
			Assert.IsNotNull(keyCtor, "Could not locate ConnectionKey primary constructor.");
			var fakeKey = keyCtor!.Invoke(new object[] { serverName, port });

			var groupType = typeof(Smb2Client).Assembly.GetType("Titanis.Smb2.ConnectionGroup");
			Assert.IsNotNull(groupType, "Could not locate internal type ConnectionGroup.");
			var groupCtor = groupType!.GetConstructor(
				BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public,
				null,
				new[] { typeof(Smb2Connection) },
				null);
			Assert.IsNotNull(groupCtor, "Could not locate ConnectionGroup(Smb2Connection) constructor.");
			var fakeConn = (Smb2Connection)RuntimeHelpers.GetUninitializedObject(typeof(Smb2Connection));
			var fakeGroup = groupCtor!.Invoke(new object[] { fakeConn });

			connections.Add(fakeKey, fakeGroup);
			Assert.AreEqual(1, connections.Count, "Precondition: cache must hold one seeded entry.");

			// ---- Attempt 1: no credentials available → production code throws
			// InvalidOperationException("No credential is available for server ...") from
			// CreateAuthContext(), which the outer catch in OpenSessionAsync must turn into
			// an eviction of the cached entry before rethrowing.
			await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
			{
				await client.GetSession(serverName, port, new Smb2SessionOptions(false), CancellationToken.None)
					.ConfigureAwait(false);
			});

			// Assertion 1: the cache must be empty after the failed auth attempt.
			Assert.AreEqual(0, connections.Count,
				"TBO-88r: auth failure must evict the cached ConnectionGroup from _connections.");
			Assert.AreEqual(0, socketService.ConnectTcpCalls,
				"First attempt used the pre-seeded cache entry, so no fresh TCP connect should have been issued.");

			// ---- Attempt 2: with the cache now empty, GetConnectionAsync must miss and call
			// ConnectToAsync, which calls ISocketService.ConnectTcp. CountingThrowingSocketService
			// records the invocation and throws, so the second call still fails — but the
			// recorded call count is what proves the dead cached entry was NOT reused.
			await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
			{
				await client.GetSession(serverName, port, new Smb2SessionOptions(false), CancellationToken.None)
					.ConfigureAwait(false);
			});

			// Assertion 2: retry must have attempted a fresh TCP connect rather than reusing
			// the dead cached connection (this is the user-observed WSAECONNRESET behavior
			// that TBO-88r fixes).
			Assert.AreEqual(1, socketService.ConnectTcpCalls,
				"TBO-88r: after eviction, retry must attempt a fresh TCP connect (proving the dead cache entry was not reused).");
		}

		/// <summary>
		/// <see cref="IClientCredentialService"/> stub that always returns <see langword="null"/>.
		/// Triggers the production "No credential is available for server ..." path inside
		/// <c>Smb2Client.OpenSessionAsync.CreateAuthContext</c>.
		/// </summary>
		private sealed class NullCredentialService : IClientCredentialService
		{
			public AuthClientContext? GetAuthContextForResource(
				string resourceType,
				object resourceKey,
				SecurityCapabilities requiredCaps,
				AuthOptions options = AuthOptions.None)
				=> null;
		}

		/// <summary>
		/// <see cref="ISocketService"/> stub that counts <see cref="ConnectTcp"/> calls and then
		/// throws. Lets the test observe whether the retry path actually reached the socket layer
		/// without requiring a real network stack.
		/// </summary>
		private sealed class CountingThrowingSocketService : ISocketService
		{
			public int ConnectTcpCalls;

			public ISocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
				=> throw new NotImplementedException("CountingThrowingSocketService.CreateSocket should not be called in TBO-88r tests.");

			public Task<ISocket> ConnectTcp(EndPoint remoteEP, CancellationToken cancellationToken)
			{
				Interlocked.Increment(ref this.ConnectTcpCalls);
				throw new SocketException((int)SocketError.HostUnreachable);
			}
		}
	}
}
