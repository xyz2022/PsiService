
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using HWND = System.IntPtr;
using System;
using System.Security.Cryptography.X509Certificates;




namespace PsiService
{

    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            [DllImport("user32.dll", SetLastError = true)]
            static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

            while (!stoppingToken.IsCancellationRequested)
            {
                //_logger.LogInformation("Worker running at: {time}", DateTimeOffset.Now);

                foreach (KeyValuePair<IntPtr, string> window in OpenWindowGetter.GetOpenWindows())
                {
                    IntPtr handle = window.Key;
                    string title = window.Value;

                    X509Certificate cert2;
                    uint u = 0;
                    _ = GetWindowThreadProcessId(handle, out u);

                    int a = (int)u;

                    Process localByName = Process.GetProcessById(a);
                    try
                    {
                        if (localByName is not null && localByName.MainModule is not null && localByName.MainModule.FileName is not null)
                        {
                            cert2 = X509Certificate.CreateFromSignedFile(localByName.MainModule.FileName);
                            if (cert2 != null)
                            {
                                if (cert2.Subject.Contains("psiphon", StringComparison.OrdinalIgnoreCase))
                                {
                                    localByName.CloseMainWindow();
                                    _logger.LogInformation("Closed Psiphon at: {time}", DateTimeOffset.Now);
                                }
                            }
                        }
                    }
                    catch
                    {

                    }
                }
                //System.Threading.Thread.Sleep(100);
                
                await Task.Delay(100, stoppingToken);
            }
        }
    }
}

public static class OpenWindowGetter
{
    /// <summary>Returns a dictionary that contains the handle and title of all the open windows.</summary>
    /// <returns>A dictionary that contains the handle and title of all the open windows.</returns>
    public static IDictionary<HWND, string> GetOpenWindows()
    {
        HWND shellWindow = GetShellWindow();
        Dictionary<HWND, string> windows = new Dictionary<HWND, string>();

        EnumWindows(delegate (HWND hWnd, int lParam)
        {
            if (hWnd == shellWindow) return true;
            if (!IsWindowVisible(hWnd)) return true;

            int length = GetWindowTextLength(hWnd);
            if (length == 0) return true;

            StringBuilder builder = new StringBuilder(length);
            GetWindowText(hWnd, builder, length + 1);

            windows[hWnd] = builder.ToString();
            return true;

        }, 0);

        return windows;
    }

    private delegate bool EnumWindowsProc(HWND hWnd, int lParam);

    [DllImport("USER32.DLL")]
    private static extern bool EnumWindows(EnumWindowsProc enumFunc, int lParam);

    [DllImport("USER32.DLL")]
    private static extern int GetWindowText(HWND hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("USER32.DLL")]
    private static extern int GetWindowTextLength(HWND hWnd);

    [DllImport("USER32.DLL")]
    private static extern bool IsWindowVisible(HWND hWnd);

    [DllImport("USER32.DLL")]
    private static extern IntPtr GetShellWindow();
}