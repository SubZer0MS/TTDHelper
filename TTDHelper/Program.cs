using System;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System.Diagnostics;
using System.Threading;
using System.IO;
using System.Runtime.InteropServices;
using System.Management;

namespace TTDHelper
{
    class TTDHelperClass
    {
        private ManualResetEvent CancelEvent = new ManualResetEvent(false);
        private const ushort ModuleDCStart_V2 = 153;
        private int sleepMs = 100;
        private string actionType = "ttd";
        private static readonly int currentProcessId = Process.GetCurrentProcess().Id;
        private TraceEventSession session;
        private string processName = string.Empty;
        private string moduleName = string.Empty;
        private ManagementEventWatcher startWatch;
        private readonly object lockObject = new object();

        TTDHelperClass(string procName, string modName, string actType, int slMs)
        {
            processName = procName;
            moduleName = modName;
            actionType = actType;
            sleepMs = slMs;
        }

        public void CollectEtwData(object o)
        {
            lock(lockObject)
            {
                session = new TraceEventSession("MicrosoftSupportCustomEtwSession_MIHSAR");
                session.Source.Dynamic.All += ProcessTraceEvent;
                session.EnableProvider("Microsoft-Windows-DotNETRuntimeRundown", TraceEventLevel.Informational, (ulong)(Keywords.Loader | Keywords.StartEnumeration));
                session.Source.Process();
            }
        }

        void WaitForProcess(object o)
        {
            startWatch = new ManagementEventWatcher(new WqlEventQuery(string.Format("select * from Win32_ProcessStartTrace where ProcessName = '{0}'", processName)));
            startWatch.EventArrived += new EventArrivedEventHandler(StartWatch_EventArrived);
            startWatch.Start();
        }

        void StartWatch_EventArrived(object sender, EventArrivedEventArgs e)
        {
            if (processName == e.NewEvent.Properties["ProcessName"].Value.ToString().ToLowerInvariant())
            {
                session.Dispose();
                Thread.Sleep(sleepMs);
                ThreadPool.QueueUserWorkItem(CollectEtwData);
            }
        }

        public void Stop()
        {
            if (session != null && session.IsActive)
            {
                session.Dispose();
                startWatch.Stop();
            }

            CancelEvent.Set();
        }

        void ProcessTraceEvent(TraceEvent traceEvent)
        {
            if (traceEvent.ProcessID == currentProcessId)
            {
                return;
            }

            if ((ushort)traceEvent.ID == ModuleDCStart_V2)
            {
                var processToUse = Process.GetProcessById(traceEvent.ProcessID);

                if (Path.GetFileNameWithoutExtension(processName) == processToUse.ProcessName.ToLowerInvariant() &&
                    moduleName == Path.GetFileName((string)traceEvent.PayloadByName("ModuleILPath")).ToLowerInvariant()
                    )
                {
                    startWatch.Stop();
                    session.Dispose();

                    switch (actionType)
                    {
                        case "ttd":

                            Console.WriteLine("Process and Module found. Attaching TTD now ...");

                            try
                            {
                                var process = Process.Start("TTTRacer.exe", string.Format("-dumpFull -attach {0}", processToUse.Id));
                                process.WaitForExit();

                                if (process.HasExited)
                                {
                                    Console.WriteLine("TTD exited with exit code: {0}", process.ExitCode);
                                }
                            }
                            catch(Exception ex)
                            {
                                Console.WriteLine("ERROR: {0}", ex.ToString());
                            }

                            break;

                        case "dmp":
                        default:

                            IntPtr hFile = IntPtr.Zero;

                            try
                            {
                                var dumpFileName = string.Concat(Path.GetFileNameWithoutExtension(processName), "_", DateTime.Now.ToString("yyyyMMddHHmmssfff"), ".dmp");

                                if (File.Exists(dumpFileName))
                                {
                                    File.Delete(dumpFileName);
                                }

                                hFile = NativeMethods.CreateFile(
                                  dumpFileName,
                                  NativeMethods.EFileAccess.GenericWrite,
                                  NativeMethods.EFileShare.None,
                                  lpSecurityAttributes: IntPtr.Zero,
                                  dwCreationDisposition: NativeMethods.ECreationDisposition.CreateAlways,
                                  dwFlagsAndAttributes: NativeMethods.EFileAttributes.Normal,
                                  hTemplateFile: IntPtr.Zero
                                );

                                if (hFile == NativeMethods.INVALID_HANDLE_VALUE)
                                {
                                    var hr = Marshal.GetHRForLastWin32Error();
                                    var ex = Marshal.GetExceptionForHR(hr);
                                    throw ex;
                                }

                                NativeMethods._MINIDUMP_TYPE dumpType = NativeMethods._MINIDUMP_TYPE.MiniDumpWithFullMemory;

                                var exceptInfo = new NativeMethods.MINIDUMP_EXCEPTION_INFORMATION();

                                if (!Is32BitProcess(processToUse) && IntPtr.Size == 4)
                                {
                                    throw new InvalidOperationException("Can't create 32 bit dump of 64 bit process");
                                }

                                Console.WriteLine("Process and Module found. Writing dump file now ...");

                                var result = NativeMethods.MiniDumpWriteDump(
                                                processToUse.Handle,
                                                processToUse.Id,
                                                hFile,
                                                dumpType,
                                                ref exceptInfo,
                                                UserStreamParam: IntPtr.Zero,
                                                CallbackParam: IntPtr.Zero
                                                );

                                if (result == false)
                                {
                                    var hr = Marshal.GetHRForLastWin32Error();
                                    var ex = Marshal.GetExceptionForHR(hr);
                                    throw ex;
                                }

                                Console.WriteLine("Dump Created. Dump is located here: {0}", dumpFileName);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("ERROR: {0}", ex.ToString());
                            }
                            finally
                            {
                                NativeMethods.CloseHandle(hFile);
                            }

                            break;
                    }

                    Stop();
                }
            }
        }

        public bool Is32BitProcess(Process proc)
        {
            bool fIs32bit = false;

            if (IntPtr.Size == 4)
            {
                fIs32bit = true;
            }

            if (NativeMethods.IsWow64Process(Process.GetCurrentProcess().Handle, out bool fIsRunningUnderWow64)
                && fIsRunningUnderWow64)
            {

                if (NativeMethods.IsWow64Process(proc.Handle, out fIsRunningUnderWow64)
                      && fIsRunningUnderWow64)
                {
                    fIs32bit = true;
                }
                else
                {
                    fIs32bit = false;
                }
            }

            return fIs32bit;
        }

        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("ERROR: To turn on ETW events you need to be Administrator, please run from an Admin process.");
                return;
            }
            
            var processName = string.Empty;
            var moduleName = string.Empty;
            var actionType = string.Empty;
            var sleepMs = 100;

            if (args.Length != 4)
            {
                Console.WriteLine("ERROR: Invalid number of arguments passed. Needed 4 arguments.");
                Console.WriteLine("\t Arg1: name of the process (with .exe included).");
                Console.WriteLine("\t Arg2: name of the managed module (with .dll included).");
                Console.WriteLine("\t Arg3: action type which accepts values of 'TTD' to attach TTD trace (needs to be in the same folder as TTTRacer.exe and related files) or 'DMP' to create a full user memory dump.");
                Console.WriteLine("\t Arg4: value in milliseconds to wait after process launch (if not already running at this point) before checking the list of loaded managed modules (DLLs) - a value of 100 can be used if unsure.");
                return;
            }

            processName = args[0].ToLowerInvariant();
            moduleName = args[1].ToLowerInvariant();
            actionType = args[2].ToLowerInvariant();
            sleepMs = int.Parse(args[3]);

            var ttdHelper = new TTDHelperClass(processName, moduleName, actionType, sleepMs);

            Console.CancelKeyPress += (o, ev) =>
            {
                ttdHelper.Stop();
            };

            ThreadPool.QueueUserWorkItem(ttdHelper.CollectEtwData);
            ThreadPool.QueueUserWorkItem(ttdHelper.WaitForProcess);

            Console.WriteLine("ProcessName: {0} and ModuleName: {1}", processName, moduleName);
            Console.WriteLine("Repro can be started now. Press Ctrl+C to stop.");

            ttdHelper.CancelEvent.WaitOne();

            Console.WriteLine("Monitoring of process/module load stopped.");
        }

        [Flags]
        public enum Keywords : long
        {
            None = 0,
            All = ~StartEnumeration,        // All does not include start-enumeration.  It just is not that useful.  
            /// <summary>
            /// Logging when garbage collections and finalization happen. 
            /// </summary>
            GC = 0x1,
            /// <summary>
            /// Events when GC handles are set or destroyed.
            /// </summary>
            GCHandle = 0x2,
            Binder = 0x4,
            /// <summary>
            /// Logging when modules actually get loaded and unloaded. 
            /// </summary>
            Loader = 0x8,
            /// <summary>
            /// Logging when Just in time (JIT) compilation occurs. 
            /// </summary>
            Jit = 0x10,
            /// <summary>
            /// Logging when precompiled native (NGEN) images are loaded.
            /// </summary>
            NGen = 0x20,
            /// <summary>
            /// Indicates that on attach or module load , a rundown of all existing methods should be done
            /// </summary>
            StartEnumeration = 0x40,
            /// <summary>
            /// Indicates that on detach or process shutdown, a rundown of all existing methods should be done
            /// </summary>
            StopEnumeration = 0x80,
            /// <summary>
            /// Events associated with validating security restrictions.
            /// </summary>
            Security = 0x400,
            /// <summary>
            /// Events for logging resource consumption on an app-domain level granularity
            /// </summary>
            AppDomainResourceManagement = 0x800,
            /// <summary>
            /// Logging of the internal workings of the Just In Time compiler.  This is fairly verbose.  
            /// It details decisions about interesting optimization (like inlining and tail call) 
            /// </summary>
            JitTracing = 0x1000,
            /// <summary>
            /// Log information about code thunks that transition between managed and unmanaged code. 
            /// </summary>
            Interop = 0x2000,
            /// <summary>
            /// Log when lock contention occurs.  (Monitor.Enters actually blocks)
            /// </summary>
            Contention = 0x4000,
            /// <summary>
            /// Log exception processing.  
            /// </summary>
            Exception = 0x8000,
            /// <summary>
            /// Log events associated with the threadpool, and other threading events.  
            /// </summary>
            Threading = 0x10000,
            /// <summary>
            /// Dump the native to IL mapping of any method that is JIT compiled.  (V4.5 runtimes and above).  
            /// </summary>
            JittedMethodILToNativeMap = 0x20000,
            /// <summary>
            /// If enabled will suppress the rundown of NGEN events on V4.0 runtime (has no effect on Pre-V4.0 runtimes).
            /// </summary>
            OverrideAndSuppressNGenEvents = 0x40000,
            /// <summary>
            /// Enables the 'BulkType' event
            /// </summary>
            Type = 0x80000,
            /// <summary>
            /// Enables the events associated with dumping the GC heap
            /// </summary>
            GCHeapDump = 0x100000,
            /// <summary>
            /// Enables allocation sampling with the 'fast'.  Sample to limit to 100 allocations per second per type.  
            /// This is good for most detailed performance investigations.   Note that this DOES update the allocation
            /// path to be slower and only works if the process start with this on. 
            /// </summary>
            GCSampledObjectAllocationHigh = 0x200000,
            /// <summary>
            /// Enables events associate with object movement or survival with each GC.  
            /// </summary>
            GCHeapSurvivalAndMovement = 0x400000,
            /// <summary>
            /// Triggers a GC.  Can pass a 64 bit value that will be logged with the GC Start event so you know which GC you actually triggered.  
            /// </summary>
            GCHeapCollect = 0x800000,
            /// <summary>
            /// Indicates that you want type names looked up and put into the events (not just meta-data tokens).
            /// </summary>
            GCHeapAndTypeNames = 0x1000000,
            /// <summary>
            /// Enables allocation sampling with the 'slow' rate, Sample to limit to 5 allocations per second per type.  
            /// This is reasonable for monitoring.    Note that this DOES update the allocation path to be slower
            /// and only works if the process start with this on.  
            /// </summary>
            GCSampledObjectAllocationLow = 0x2000000,
            /// <summary>
            /// Turns on capturing the stack and type of object allocation made by the .NET Runtime.   This is only
            /// supported after V4.5.3 (Late 2014)   This can be very verbose and you should seriously using  GCSampledObjectAllocationHigh
            /// instead (and GCSampledObjectAllocationLow for production scenarios).  
            /// </summary>
            GCAllObjectAllocation = GCSampledObjectAllocationHigh | GCSampledObjectAllocationLow,
            /// <summary>
            /// This suppresses NGEN events on V4.0 (where you have NGEN PDBs), but not on V2.0 (which does not know about this 
            /// bit and also does not have NGEN PDBS).  
            /// </summary>
            SupressNGen = 0x40000,
            /// <summary>
            /// TODO document
            /// </summary>
            PerfTrack = 0x20000000,
            /// <summary>
            /// Also log the stack trace of events for which this is valuable.
            /// </summary>
            Stack = 0x40000000,
            /// <summary>
            /// This allows tracing work item transfer events (thread pool enqueue/dequeue/ioenqueue/iodequeue/a.o.)
            /// </summary>
            ThreadTransfer = 0x80000000L,
            /// <summary>
            /// .NET Debugger events
            /// </summary>
            Debugger = 0x100000000,
            /// <summary>
            /// Events intended for monitoring on an ongoing basis.  
            /// </summary>
            Monitoring = 0x200000000,
            /// <summary>
            /// Events that will dump PDBs of dynamically generated assemblies to the ETW stream.  
            /// </summary>
            Codesymbols = 0x400000000,
            /// <summary>
            /// Diagnostic events for diagnosing compilation and pre-compilation features.
            /// </summary>
            CompilationDiagnostic = 0x2000000000,

            /// <summary>
            /// Recommend default flags (good compromise on verbosity).  
            /// </summary>
            Default = GC | Type | GCHeapSurvivalAndMovement | Binder | Loader | Jit | NGen | SupressNGen
                         | StopEnumeration | Security | AppDomainResourceManagement | Exception | Threading | Contention | Stack | JittedMethodILToNativeMap
                         | ThreadTransfer | GCHeapAndTypeNames | Codesymbols,

            /// <summary>
            /// What is needed to get symbols for JIT compiled code.  
            /// </summary>
            JITSymbols = Jit | StopEnumeration | JittedMethodILToNativeMap | SupressNGen | Loader,

            /// <summary>
            /// This provides the flags commonly needed to take a heap .NET Heap snapshot with ETW.  
            /// </summary>
            GCHeapSnapshot = GC | GCHeapCollect | GCHeapDump | GCHeapAndTypeNames | Type,
        };
    }

    public static partial class NativeMethods
    {
        [DllImport("Dbghelp.dll")]
        public static extern bool MiniDumpWriteDump(
            IntPtr hProcess,
            int ProcessId,
            IntPtr hFile,
            _MINIDUMP_TYPE DumpType,
            ref MINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
            IntPtr UserStreamParam,
            IntPtr CallbackParam
            );

        [Flags]
        public enum _MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000,
            MiniDumpWithoutAuxiliaryState = 0x00004000,
            MiniDumpWithFullAuxiliaryState = 0x00008000,
            MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
            MiniDumpIgnoreInaccessibleMemory = 0x00020000,
            MiniDumpWithTokenInformation = 0x00040000,
            MiniDumpWithModuleHeaders = 0x00080000,
            MiniDumpFilterTriage = 0x00100000,
            MiniDumpValidTypeFlags = 0x001fffff,
        };

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct MINIDUMP_EXCEPTION_INFORMATION
        {
            public uint ThreadId;
            public IntPtr ExceptionPointers;
            public int ClientPointers;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFile(
                string lpFileName,
                EFileAccess dwDesiredAccess,
                EFileShare dwShareMode,
                IntPtr lpSecurityAttributes,
                ECreationDisposition dwCreationDisposition,
                EFileAttributes dwFlagsAndAttributes,
                IntPtr hTemplateFile
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        public static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        [Flags]
        public enum EFileAccess : uint
        {
            //
            // Standart Section
            //

            AccessSystemSecurity = 0x1000000,   // AccessSystemAcl access type
            MaximumAllowed = 0x2000000,     // MaximumAllowed access type

            Delete = 0x10000,
            ReadControl = 0x20000,
            WriteDAC = 0x40000,
            WriteOwner = 0x80000,
            Synchronize = 0x100000,

            StandardRightsRequired = 0xF0000,
            StandardRightsRead = ReadControl,
            StandardRightsWrite = ReadControl,
            StandardRightsExecute = ReadControl,
            StandardRightsAll = 0x1F0000,
            SpecificRightsAll = 0xFFFF,

            FILE_READ_DATA = 0x0001,        // file & pipe
            FILE_LIST_DIRECTORY = 0x0001,       // directory
            FILE_WRITE_DATA = 0x0002,       // file & pipe
            FILE_ADD_FILE = 0x0002,         // directory
            FILE_APPEND_DATA = 0x0004,      // file
            FILE_ADD_SUBDIRECTORY = 0x0004,     // directory
            FILE_CREATE_PIPE_INSTANCE = 0x0004, // named pipe
            FILE_READ_EA = 0x0008,          // file & directory
            FILE_WRITE_EA = 0x0010,         // file & directory
            FILE_EXECUTE = 0x0020,          // file
            FILE_TRAVERSE = 0x0020,         // directory
            FILE_DELETE_CHILD = 0x0040,     // directory
            FILE_READ_ATTRIBUTES = 0x0080,      // all
            FILE_WRITE_ATTRIBUTES = 0x0100,     // all

            //
            // Generic Section
            //

            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000,

            SPECIFIC_RIGHTS_ALL = 0x00FFFF,
            FILE_ALL_ACCESS =
            StandardRightsRequired |
            Synchronize |
            0x1FF,

            FILE_GENERIC_READ =
            StandardRightsRead |
            FILE_READ_DATA |
            FILE_READ_ATTRIBUTES |
            FILE_READ_EA |
            Synchronize,

            FILE_GENERIC_WRITE =
            StandardRightsWrite |
            FILE_WRITE_DATA |
            FILE_WRITE_ATTRIBUTES |
            FILE_WRITE_EA |
            FILE_APPEND_DATA |
            Synchronize,

            FILE_GENERIC_EXECUTE =
            StandardRightsExecute |
              FILE_READ_ATTRIBUTES |
              FILE_EXECUTE |
              Synchronize
        }

        [Flags]
        public enum EFileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004
        }

        public enum ECreationDisposition : uint
        {
            New = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5
        }

        [Flags]
        public enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }


        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process(
              [In] IntPtr hProcess,
              [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process
              );

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();
    }
}