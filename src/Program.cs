using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace XlsxRsaLock;

internal static class Program
{
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);

    [STAThread]
    private static int Main(string[] args)
    {
        if (args is ["render-ui", var png])  // draws the window into a PNG for the README, off-screen
        {
            ApplicationConfiguration.Initialize();
            using var form = new MainForm { StartPosition = FormStartPosition.Manual, Location = new Point(-3000, -3000), ShowInTaskbar = false };
            form.Show();
            Application.DoEvents();
            using var bmp = new Bitmap(form.Width, form.Height);
            form.DrawToBitmap(bmp, new Rectangle(Point.Empty, form.Size));
            bmp.Save(png, System.Drawing.Imaging.ImageFormat.Png);
            return 0;
        }
        if (args.Length > 0)
        {
            AttachConsole(-1); // print to the calling terminal
            return Cli(args);
        }
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }

    /// <summary>
    ///   XlsxRsaLock keygen  &lt;bits&gt; &lt;public.pem&gt; &lt;private.pem&gt; [password]
    ///   XlsxRsaLock encrypt &lt;file&gt; &lt;public.pem&gt; &lt;out.xrsa&gt; [pure|hybrid]
    ///   XlsxRsaLock decrypt &lt;file.xrsa&gt; &lt;private.pem&gt; &lt;out&gt; [password]
    ///   XlsxRsaLock selftest &lt;file&gt;
    /// </summary>
    private static int Cli(string[] a)
    {
        try
        {
            switch (a[0])
            {
                case "keygen":
                    var (pub, priv) = RsaFileCrypto.CreateKeyPair(int.Parse(a[1]), a.ElementAtOrDefault(4));
                    File.WriteAllText(a[2], pub); File.WriteAllText(a[3], priv);
                    Console.WriteLine($"Created {a[1]}-bit key pair: {a[2]}, {a[3]}");
                    return 0;
                case "encrypt":
                    using (var k = RsaFileCrypto.LoadKey(File.ReadAllText(a[2])))
                        RsaFileCrypto.Encrypt(a[1], a[3], k, a.ElementAtOrDefault(4) == "hybrid" ? CipherMode.Hybrid : CipherMode.PureRsa);
                    Console.WriteLine($"Encrypted {a[1]} -> {a[3]}");
                    return 0;
                case "decrypt":
                    using (var k = RsaFileCrypto.LoadKey(File.ReadAllText(a[2]), a.ElementAtOrDefault(4)))
                        RsaFileCrypto.Decrypt(a[1], a[3], k);
                    Console.WriteLine($"Decrypted {a[1]} -> {a[3]} (SHA-256 verified)");
                    return 0;
                case "selftest":
                    return SelfTest(a[1]);
            }
            Console.Error.WriteLine("Unknown command. Use keygen, encrypt, decrypt or selftest.");
            return 2;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("Error: " + e.Message);
            return 1;
        }
    }

    private static int SelfTest(string file)
    {
        string dir = Path.Combine(Path.GetTempPath(), "xrsa-selftest-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        string original = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file)));
        Console.WriteLine($"file {Path.GetFileName(file)}  {new FileInfo(file).Length:N0} bytes  sha256 {original[..16]}...");
        bool ok = true;
        foreach (int bits in new[] { 2048, 3072, 4096 })
        {
            var (pub, priv) = RsaFileCrypto.CreateKeyPair(bits, "test-password");
            using var pubKey = RsaFileCrypto.LoadKey(pub);
            using var privKey = RsaFileCrypto.LoadKey(priv, "test-password");
            foreach (var mode in new[] { CipherMode.PureRsa, CipherMode.Hybrid })
            {
                string enc = Path.Combine(dir, $"{bits}-{mode}.xrsa"), dec = Path.Combine(dir, $"{bits}-{mode}.xlsx");
                var sw = Stopwatch.StartNew();
                RsaFileCrypto.Encrypt(file, enc, pubKey, mode);
                long encMs = sw.ElapsedMilliseconds; sw.Restart();
                RsaFileCrypto.Decrypt(enc, dec, privKey);
                long decMs = sw.ElapsedMilliseconds;
                string back = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(dec)));
                bool same = back == original;
                ok &= same;
                Console.WriteLine($"RSA-{bits} {mode,-7}  encrypt {encMs,6} ms  decrypt {decMs,6} ms  size {new FileInfo(enc).Length,10:N0}  identical: {same}");
            }
            // wrong key must be rejected, not silently produce garbage
            var (_, otherPriv) = RsaFileCrypto.CreateKeyPair(bits, null);
            using var wrong = RsaFileCrypto.LoadKey(otherPriv);
            try { RsaFileCrypto.Decrypt(Path.Combine(dir, $"{bits}-PureRsa.xrsa"), Path.Combine(dir, "wrong.xlsx"), wrong); ok = false; Console.WriteLine("  wrong key accepted!"); }
            catch (CryptographicException) { Console.WriteLine($"RSA-{bits} wrong private key rejected: True"); }
        }
        Directory.Delete(dir, true);
        Console.WriteLine(ok ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
        return ok ? 0 : 1;
    }
}
