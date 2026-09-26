using System.Security.Cryptography;

namespace XlsxRsaLock;

/// <summary>Three steps for non-technical users: create keys, lock a file, unlock a file.</summary>
public sealed class MainForm : Form
{
    private readonly TextBox _log = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, Font = new Font("Consolas", 9.5f), BackColor = Color.FromArgb(250, 250, 247) };
    private readonly ProgressBar _progress = new() { Dock = DockStyle.Bottom, Height = 10 };
    private readonly ComboBox _bits = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private readonly ComboBox _mode = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 210 };

    public MainForm()
    {
        Text = "XlsxRsaLock - RSA file locker";
        MinimumSize = new Size(760, 520);
        Size = new Size(820, 560);
        Font = new Font("Segoe UI", 10f);
        BackColor = Color.White;

        _bits.Items.AddRange(["2048", "3072", "4096"]); _bits.SelectedIndex = 1;
        _mode.Items.AddRange(["Pure RSA only", "RSA + AES-256-GCM (faster)"]); _mode.SelectedIndex = 0;

        var steps = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 3, Padding = new Padding(16, 16, 16, 8) };
        steps.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33)); steps.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33)); steps.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
        steps.Controls.Add(Card("1  Create keys", "Make a key pair. Share the public key; keep the private key safe.", "Create key pair...", CreateKeys, _bits), 0, 0);
        steps.Controls.Add(Card("2  Lock a file", "Encrypt any .xlsx with a public key.", "Choose file to lock...", LockFile, _mode), 1, 0);
        steps.Controls.Add(Card("3  Unlock a file", "Decrypt with the private key. The result is checked against the original SHA-256.", "Choose file to unlock...", UnlockFile, null), 2, 0);

        var logPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(16, 0, 16, 16) };
        logPanel.Controls.Add(_log);
        Controls.Add(logPanel); Controls.Add(_progress); Controls.Add(steps);
        Log("Ready. Locked files get the .xrsa extension and can only be opened with the matching private key.");
    }

    private static Control Card(string title, string text, string button, Func<Task> action, Control? option)
    {
        var p = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, Dock = DockStyle.Fill, AutoSize = true, Padding = new Padding(12), Margin = new Padding(6), BackColor = Color.FromArgb(244, 247, 241), WrapContents = false };
        p.Controls.Add(new Label { Text = title, AutoSize = true, Font = new Font("Segoe UI Semibold", 12f), ForeColor = Color.FromArgb(37, 48, 42) });
        p.Controls.Add(new Label { Text = text, MaximumSize = new Size(220, 0), AutoSize = true, ForeColor = Color.FromArgb(95, 109, 99), Margin = new Padding(3, 4, 3, 8) });
        if (option != null) p.Controls.Add(option);
        var b = new Button { Text = button, AutoSize = true, Margin = new Padding(3, 8, 3, 3), BackColor = Color.FromArgb(71, 113, 90), ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
        b.Click += async (_, _) => { b.Enabled = false; try { await action(); } finally { b.Enabled = true; } };
        p.Controls.Add(b);
        return p;
    }

    private void Log(string line) => _log.AppendText($"{DateTime.Now:HH:mm:ss}  {line}{Environment.NewLine}");

    private Progress<double> Progress() => new(v => _progress.Value = (int)Math.Clamp(v * 100, 0, 100));

    private async Task CreateKeys()
    {
        using var dlg = new FolderBrowserDialog { Description = "Where should the two key files be saved?" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        string? password = PasswordDialog.Ask(this, "Protect the private key with a password (recommended). Leave empty for no password.", confirm: true);
        if (password == null) return;
        int bits = int.Parse((string)_bits.SelectedItem!);
        Log($"Generating a {bits}-bit RSA key pair...");
        var (pub, priv) = await Task.Run(() => RsaFileCrypto.CreateKeyPair(bits, password));
        string pubPath = Path.Combine(dlg.SelectedPath, "public_key.pem"), privPath = Path.Combine(dlg.SelectedPath, "private_key.pem");
        if ((File.Exists(pubPath) || File.Exists(privPath)) &&
            MessageBox.Show(this, "Key files already exist in this folder. Overwrite them?", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;
        File.WriteAllText(pubPath, pub); File.WriteAllText(privPath, priv);
        Log($"Saved {pubPath}");
        Log($"Saved {privPath}{(password.Length > 0 ? " (password protected)" : "")}. Back this file up: without it locked files cannot be opened.");
    }

    private async Task LockFile()
    {
        using var open = new OpenFileDialog { Title = "Choose the file to lock", Filter = "Excel workbooks (*.xlsx)|*.xlsx|All files (*.*)|*.*" };
        if (open.ShowDialog(this) != DialogResult.OK) return;
        using var key = new OpenFileDialog { Title = "Choose the PUBLIC key", Filter = "PEM key (*.pem)|*.pem|All files (*.*)|*.*" };
        if (key.ShowDialog(this) != DialogResult.OK) return;
        using var save = new SaveFileDialog { Title = "Save locked file as", FileName = Path.GetFileName(open.FileName) + ".xrsa", Filter = "Locked file (*.xrsa)|*.xrsa" };
        if (save.ShowDialog(this) != DialogResult.OK) return;
        var mode = _mode.SelectedIndex == 0 ? CipherMode.PureRsa : CipherMode.Hybrid;
        try
        {
            using var rsa = RsaFileCrypto.LoadKey(File.ReadAllText(key.FileName));
            if (rsa.KeySize < 2048) throw new CryptographicException("Please use a key of at least 2048 bits.");
            Log($"Locking {Path.GetFileName(open.FileName)} with RSA-{rsa.KeySize} ({mode})...");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await Task.Run(() => RsaFileCrypto.Encrypt(open.FileName, save.FileName, rsa, mode, Progress()));
            Log($"Done in {sw.Elapsed.TotalSeconds:F1}s -> {save.FileName}");
        }
        catch (Exception e) { Fail(e); }
    }

    private async Task UnlockFile()
    {
        using var open = new OpenFileDialog { Title = "Choose the locked file", Filter = "Locked file (*.xrsa)|*.xrsa|All files (*.*)|*.*" };
        if (open.ShowDialog(this) != DialogResult.OK) return;
        using var key = new OpenFileDialog { Title = "Choose the PRIVATE key", Filter = "PEM key (*.pem)|*.pem|All files (*.*)|*.*" };
        if (key.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var header = RsaFileCrypto.ReadHeader(open.FileName);
            using var save = new SaveFileDialog { Title = "Save unlocked file as", FileName = header.OriginalName };
            if (save.ShowDialog(this) != DialogResult.OK) return;
            string pem = File.ReadAllText(key.FileName);
            string? password = null;
            if (RsaFileCrypto.IsPasswordProtected(pem) && (password = PasswordDialog.Ask(this, "Password for the private key:", confirm: false)) == null) return;
            using var rsa = RsaFileCrypto.LoadKey(pem, password);
            Log($"Unlocking {Path.GetFileName(open.FileName)} (RSA-{header.KeyBits}, {header.Mode})...");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await Task.Run(() => RsaFileCrypto.Decrypt(open.FileName, save.FileName, rsa, Progress()));
            Log($"Done in {sw.Elapsed.TotalSeconds:F1}s. SHA-256 matches the original: the file is bit-for-bit identical -> {save.FileName}");
        }
        catch (Exception e) { Fail(e); }
    }

    private void Fail(Exception e)
    {
        _progress.Value = 0;
        Log("Error: " + e.Message);
        MessageBox.Show(this, e.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}

internal static class PasswordDialog
{
    /// <summary>Returns the password (possibly empty), or null when cancelled.</summary>
    public static string? Ask(IWin32Window owner, string prompt, bool confirm)
    {
        using var f = new Form { Text = "Password", FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false, ClientSize = new Size(380, confirm ? 170 : 130), Font = new Font("Segoe UI", 10f) };
        var label = new Label { Text = prompt, Location = new Point(12, 10), Size = new Size(356, 40) };
        var p1 = new TextBox { UseSystemPasswordChar = true, Location = new Point(12, 52), Width = 356 };
        var p2 = new TextBox { UseSystemPasswordChar = true, Location = new Point(12, 86), Width = 356, PlaceholderText = "Repeat password", Visible = confirm };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(212, confirm ? 124 : 88), Width = 75 };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(293, confirm ? 124 : 88), Width = 75 };
        f.Controls.AddRange([label, p1, p2, ok, cancel]); f.AcceptButton = ok; f.CancelButton = cancel;
        while (f.ShowDialog(owner) == DialogResult.OK)
        {
            if (!confirm || p1.Text == p2.Text) return p1.Text;
            MessageBox.Show(f, "The two passwords are different.", "Password", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        return null;
    }
}
