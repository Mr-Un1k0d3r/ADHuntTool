using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Collections;
using System.Security.Principal;
using System.ServiceProcess;
using System.Security.AccessControl;

namespace ADHuntTool
{

    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        public static bool showACL = false;

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr a, UInt32 b);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("Netapi32.dll")]
        static extern int NetLocalGroupEnum([In, MarshalAs(UnmanagedType.LPWStr)] string computerName, int level, out IntPtr bufPtr, int prefMaxLen, out int entriesRead, out int totalEntries, ref int resumeHandle);

        [DllImport("netapi32.dll")]
        static extern int NetLocalGroupGetMembers([In, MarshalAs(UnmanagedType.LPWStr)] string computerName, [In, MarshalAs(UnmanagedType.LPWStr)] string localGroupName, int level, out IntPtr bufPtr, int prefMaxLen, out int entriesRead, out int totalEntries, ref int resumeHandle);

        [DllImport("netapi32.dll")]
        static extern int NetWkstaUserEnum([In, MarshalAs(UnmanagedType.LPWStr)] string computerName, int level, out IntPtr bufPtr, int prefMaxLen, ref int entriesRead, ref int totalEntries, ref int resumeHandle);

        [DllImport("advapi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LogonUser([In, MarshalAs(UnmanagedType.LPStr)] string lpszUsername, [In, MarshalAs(UnmanagedType.LPStr)] string lpszDomain, [In, MarshalAs(UnmanagedType.LPStr)] string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("advapi32.dll")]
        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(string ServerName, int level, ref IntPtr bufPtr, uint prefmaxlen, ref int entriesread, ref int totalentries, ref int resume_handle);

        [DllImport("netapi32.dll")]
        private static extern int NetSessionEnum([In, MarshalAs(UnmanagedType.LPWStr)] string ServerName, [In, MarshalAs(UnmanagedType.LPWStr)] string UncClientName, [In, MarshalAs(UnmanagedType.LPWStr)] string UserName, Int32 Level, out IntPtr bufptr, int prefmaxlen, ref Int32 entriesread, ref Int32 totalentries, ref Int32 resume_handle);
        [DllImport("Netapi32.dll")]
        static extern uint NetApiBufferFree(IntPtr buffer);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseServiceHandle(IntPtr hSCObject);

        [StructLayout(LayoutKind.Sequential)]
        internal struct LOCALGROUP_USERS_INFO_1
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string name;
            [MarshalAs(UnmanagedType.LPWStr)] public string comment;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public int lgrmi2_sidusage;
            [MarshalAs(UnmanagedType.LPWStr)] public string lgrmi2_domainandname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct SESSION_INFO_10
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_cname;
            [MarshalAs(UnmanagedType.LPWStr)] public string sesi10_username;
            public int sesi10_time;
            public int sesi10_idle_time;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WKSTA_USER_INFO_1
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string wkui1_username;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string wkui1_logon_domain;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string wkui1_oth_domains;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string wkui1_logon_server;
        }

        static int NERR_Success = 0;
        static int MAX_PREFERRED_LENGTH = -1;
        static uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        static string SERVICES_ACTIVE_DATABASE = "ServicesActive";
        static int max_threadpool = 20;
        static void ShowDebug(Exception e, bool show)
        {
            if (show)
            {
                Console.WriteLine("DEBUG: {0}", e.Message.ToString());
            }
        }

        static void DumpLocalAdminGroups(string computer)
        {
            IntPtr bufPtr = IntPtr.Zero;
            int entriesRead = 0;
            int totalEntries = 0;
            int resumeHandle = 0;
            int output = NetLocalGroupEnum(computer, 1, out bufPtr, MAX_PREFERRED_LENGTH, out entriesRead, out totalEntries, ref resumeHandle);
            long offset = bufPtr.ToInt64();

            if (output == NERR_Success && offset > 0)
            {
                int position = Marshal.SizeOf(typeof(LOCALGROUP_USERS_INFO_1));
                Console.WriteLine("\nComputer {0}\n------------------------", computer);
                for (int i = 0; i < entriesRead; i++)
                {
                    IntPtr nextPtr = new IntPtr(offset);
                    LOCALGROUP_USERS_INFO_1 data = (LOCALGROUP_USERS_INFO_1)Marshal.PtrToStructure(nextPtr, typeof(LOCALGROUP_USERS_INFO_1));
                    offset = nextPtr.ToInt64() + position;
                    Console.WriteLine(data.name);
                    DumpLocalAdminMembers(computer, data.name);
                }
                NetApiBufferFree(bufPtr);
            }
            else
            {
                Console.WriteLine("Error: Could not list local group for the {0} system. Error {1}.", computer, output);
            }
        }

        static void DumpRemoteSession(string computer)
        {
            IntPtr bufPtr = IntPtr.Zero;
            int entriesRead = 0;
            int totalEntries = 0;
            int resumeHandle = 0;
            int output = NetSessionEnum(computer, null, null, 10, out bufPtr, -1, ref entriesRead, ref totalEntries, ref resumeHandle);
            long offset = bufPtr.ToInt64();

            Console.WriteLine("\nComputer {0}\n------------------------", computer);
            if (output == NERR_Success && offset > 0)
            {
                int position = Marshal.SizeOf(typeof(SESSION_INFO_10));

                for (int i = 0; i < entriesRead; i++)
                {
                    IntPtr nextPtr = new IntPtr(offset);
                    SESSION_INFO_10 data = (SESSION_INFO_10)Marshal.PtrToStructure(nextPtr, typeof(SESSION_INFO_10));
                    offset = nextPtr.ToInt64() + position;
                    Console.WriteLine("sesi10_cname: {0}", data.sesi10_cname);
                    Console.WriteLine("sesi10_username: {0}", data.sesi10_username);
                }
                NetApiBufferFree(bufPtr);
            }
        }

        static void DumpWkstaSession(string computer)
        {
            IntPtr bufPtr = IntPtr.Zero;
            int entriesRead = 0;
            int totalEntries = 0;
            int resumeHandle = 0;
            int output = NetWkstaUserEnum(computer, 1, out bufPtr, -1, ref entriesRead, ref totalEntries, ref resumeHandle);
            long offset = bufPtr.ToInt64();

            Console.WriteLine("\nComputer {0}\n------------------------", computer);
            if (output == NERR_Success && offset > 0)
            {
                int position = Marshal.SizeOf(typeof(WKSTA_USER_INFO_1));

                for (int i = 0; i < entriesRead; i++)
                {
                    IntPtr nextPtr = new IntPtr(offset);
                    WKSTA_USER_INFO_1 data = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(nextPtr, typeof(WKSTA_USER_INFO_1));
                    offset = nextPtr.ToInt64() + position;
                    Console.WriteLine("wkui1_username: {0}", data.wkui1_username);
                    Console.WriteLine("wkui1_logon_domain: {0}", data.wkui1_logon_domain);
                    Console.WriteLine("wkui1_oth_domains: {0}", data.wkui1_oth_domains);
                    Console.WriteLine("wkui1_logon_server: {0}", data.wkui1_logon_server);
                }
                NetApiBufferFree(bufPtr);
            }
        }


        static void DumpLocalAdminMembers(string computer, string group)
        {
            IntPtr bufPtr = IntPtr.Zero;
            int entriesRead = 0;
            int totalEntries = 0;
            int resumeHandle = 0;
            int output = NetLocalGroupGetMembers(computer, group, 2, out bufPtr, MAX_PREFERRED_LENGTH, out entriesRead, out totalEntries, ref resumeHandle);
            long offset = bufPtr.ToInt64();

            if (output == NERR_Success && offset > 0)
            {
                int position = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));
                for (int i = 0; i < entriesRead; i++)
                {
                    IntPtr nextPtr = new IntPtr(offset);
                    LOCALGROUP_MEMBERS_INFO_2 data = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(nextPtr, typeof(LOCALGROUP_MEMBERS_INFO_2));
                    offset = nextPtr.ToInt64() + position;
                    Console.WriteLine(data.lgrmi2_domainandname);
                }
                NetApiBufferFree(bufPtr);
            }
        }

        static void CheckLocalAdminRight(string computer)
        {
            IntPtr handle = OpenSCManager(computer, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
            if (handle != IntPtr.Zero)
            {
                Console.WriteLine("{0} admin on: {1}", WindowsIdentity.GetCurrent().Name, computer);
                CloseServiceHandle(handle);
            }
        }

        static string FormatProperties(ResultPropertyValueCollection r)
        {
            StringBuilder sb = new StringBuilder();
            Int32 size = r.Count;
            for (Int32 i = 0; i < size; i++)
            {
                if (r[i].GetType().ToString() == "System.Byte[]")
                {
                    sb.Append(Encoding.ASCII.GetString((byte[])r[i]) + ",");
                }
                else
                {
                    sb.Append(r[i] + ",");
                }


            }
            return sb.ToString().TrimEnd(',');
        }

        static string FormatTime(object p)
        {
            // I will assume that all Int64 are timestamp
            if (p.GetType().ToString() == "System.Int64")
            {
                return DateTime.FromFileTime((long)p).ToString();
            }

            if(p.GetType().ToString() == "System.Byte[]")
            {
                try {
                    SecurityIdentifier si = new SecurityIdentifier((byte[])p, 0);
                    string output = si.ToString();
                    return output;
                }
                catch
                {
                    return Encoding.ASCII.GetString((byte[])p);
                }
            }
            return p.ToString(); ;
        }
        static string FormatCertFlag(string flag)
        {
            StringBuilder sb = new StringBuilder();
            UInt32 flags = UInt32.Parse(flag);

            if ((flags & 0x01) == 0x01)
            {
                sb.Append("CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,");
            }
            if ((flags & 0x00010000) == 0x00010000)
            {
                sb.Append("CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME,");
            }
            if ((flags & 0x00400000) == 0x00400000)
            {
                sb.Append("CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS,");
            }
            if ((flags & 0x00800000) == 0x00800000)
            {
                sb.Append("CT_FLAG_SUBJECT_ALT_REQUIRE_SPN,");
            }
            if ((flags & 0x01000000) == 0x01000000)
            {
                sb.Append("CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID,");
            }
            if ((flags & 0x02000000) == 0x02000000)
            {
                sb.Append("CT_FLAG_SUBJECT_ALT_REQUIRE_UPN ,");
            }
            if ((flags & 0x04000000) == 0x04000000)
            {
                sb.Append("CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL,");
            }
            if ((flags & 0x08000000) == 0x08000000)
            {
                sb.Append("CT_FLAG_SUBJECT_ALT_REQUIRE_DNS,");
            }
            if ((flags & 0x10000000) == 0x10000000)
            {
                sb.Append("CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN,");
            }
            if ((flags & 0x20000000) == 0x20000000)
            {
                sb.Append("CT_FLAG_SUBJECT_REQUIRE_EMAIL,");
            }
            if ((flags & 0x40000000) == 0x40000000)
            {
                sb.Append("CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME,");
            }
            if ((flags & 0x80000000) == 0x80000000)
            {
                sb.Append("CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH,");
            }
            if ((flags & 0x00000008) == 0x00000008)
            {
                sb.Append("CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME,");
            }

            return sb.ToString();
        }

        static string FormatSDDL(ResultPropertyValueCollection r)
        {
            StringBuilder sb = new StringBuilder();
            Int32 size = r.Count;
            for (Int32 i = 0; i < size; i++)
            {
                RawSecurityDescriptor raw = new RawSecurityDescriptor((byte[])r[i], 0);


                sb.Append(SDDLParser.Parse(raw.GetSddlForm(AccessControlSections.All)) + ",");


            }
            return sb.ToString().TrimEnd(',');
        }
        static List<string> LdapQuery(string domain, string query, string properties, bool showNull = true, bool returnList = false, string prepend = "LDAP://")
        {
            domain = prepend + domain;
            List<string> output = new List<string>();
            Console.WriteLine("Connecting to: {0}", domain);
            Console.WriteLine("Querying:      {0}", query);


            DirectoryEntry de = new DirectoryEntry(domain);
            DirectorySearcher ds = new DirectorySearcher(de);

            ds.Filter = query;
            ds.PageSize = Int32.MaxValue;

            if (Program.showACL)
            {
                ds.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Group;
            }

            foreach (SearchResult r in ds.FindAll())
            {
                try
                {
                    StringBuilder sb = new StringBuilder();
                    if (Program.showACL)
                    {
                        sb.Append("ntSecurityDescriptor" + new string(' ', 24 - "ntSecurityDescriptor".Length) + ": ");
                        sb.Append(FormatSDDL(r.Properties["ntSecurityDescriptor"]));
                        sb.Append("\r\n");
                    }
                    foreach (string prop in properties.Split(','))
                    {
                        if (prop.ToLower().StartsWith("managed") && r.Properties[prop].Count <= 0)
                        {
                            break;
                        }
                        Int32 item = r.Properties[prop].Count;
                        if (item > 0)
                        {
                            if (prop.Length >= 24)
                            {
                                sb.Append(prop + ": ");
                            }
                            else
                            {
                                sb.Append(prop + new string(' ', 24 - prop.Length) + ": ");
                            }

                            if (prop == "msPKI-Certificate-Name-Flag")
                            {
                                sb.Append(FormatCertFlag(r.Properties[prop][0].ToString()));
                            }
                            else
                            {
                                sb.Append(item > 1 ? "[" + FormatProperties(r.Properties[prop]) + "]" : FormatTime(r.Properties[prop][0]));
                                sb.Append("\r\n");
                            }

                            if (returnList)
                            {
                                output.Add(r.Properties[prop][0].ToString());
                            }
                        }
                        else
                        {
                            if (showNull)
                            {
                                if (prop.Length >= 24)
                                {
                                    sb.Append(prop + ": ");
                                }
                                else
                                {
                                    sb.Append(prop + new string(' ', 24 - prop.Length) + ":\r\n");
                                }
                            }
                        }

                    }
                    if (sb.Length > 0)
                    {
                        if (!returnList)
                        {
                            Console.WriteLine(sb.ToString());
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("ERROR: {0}", e.Message.ToString());
                }
            }
            return output;
        }

        static bool ListFilesSearchForManaged(string path, bool verbose = false)
        {
            Console.WriteLine("Searching GPOs located at " + path);
            bool managedFound = false;
            foreach (string directory in Directory.GetDirectories(path))
            {
                foreach (string subdirectory in Directory.GetDirectories(directory))
                {
                    if (subdirectory.ToLower().EndsWith("policies"))
                    {
                        foreach (string policy in Directory.GetDirectories(subdirectory))
                        {
                            try
                            {
                                foreach (string file in Directory.GetFiles(policy + "\\machine\\preferences\\groups\\"))
                                {
                                    if (file.ToLower().EndsWith("groups.xml"))
                                    {
                                        using (StreamReader reader = new StreamReader(file))
                                        {
                                            string data = reader.ReadToEnd();
                                            if (data.Contains("(objectCategory=user)(objectClass=user)(distinguishedName=%managedBy%)"))
                                            {
                                                managedFound = true;
                                                Console.WriteLine(file + " contained managedby information");
                                                if (verbose)
                                                {
                                                    Console.WriteLine(data);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                }
            }
            return managedFound;
        }


        static void Main(string[] args)
        {
            bool verboseDebug = Array.Exists(args, match => match.ToLower() == "-verbose");
            Program.showACL = Array.Exists(args, match => match.ToLower() == "-acl");

            ThreadPool.SetMaxThreads(max_threadpool, max_threadpool);

            // ShowWindow(GetConsoleWindow(), 0);
            if (args.Length >= 2)
            {
                string option = args[0].ToLower();
                string domain = args[1];

                if (option == "passwordbruteforce")
                {
                    Console.WriteLine("Starting password brute force");
                    string query = "";
                    string properties = "samaccountname";
                    string filter = "";

                    try
                    {
                        filter = "(samaccountname=*" + args[3] + "*)";
                    }
                    catch
                    {
                        filter = "";
                    }

                    try
                    {
                        query = "(&(objectClass=user)" + filter + ")";
                        List<string> users = LdapQuery(domain, query, properties, false, true);
                        Console.WriteLine("Bruteforcing {0} accounts", users.Count);
                        foreach (string u in users)
                        {
                            Thread t = new Thread(() =>
                            {
                                using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, domain))
                                {
                                    if (verboseDebug)
                                    {
                                        Console.WriteLine("Password brute force against {0}\\{1}", domain, u);
                                    }
                                    // validate the credentials
                                    if (pc.ValidateCredentials(u, args[2]))
                                    {
                                        Console.WriteLine("[SUCCESS] {0}\\{1} password is {2}", domain, u, args[2]);
                                    }
                                }
                            });
                            t.SetApartmentState(ApartmentState.STA);
                            t.Start();
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: PasswordBruteForce catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpallusers")
                {
                    string query = "";
                    string properties = "name,givenname,displayname,samaccountname,objectsid,adspath,distinguishedname,memberof,ou,mail,proxyaddresses,lastlogon,pwdlastset,mobile,streetaddress,co,title,department,description,comment,badpwdcount,objectcategory,userpassword,scriptpath,managedby,managedobjects";
                    try
                    {
                        query = "(&(objectClass=user))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpAllUsers catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumplocalgroup")
                {
                    string query = "";
                    string properties = "name";
                    string computername = "";

                    try
                    {
                        computername = "(name=*" + args[2] + "*)";
                    }
                    catch
                    {
                        computername = "";
                    }

                    try
                    {
                        query = "(&(objectClass=computer)" + computername + ")";
                        List<string> computers = LdapQuery(domain, query, properties, false, true);
                        Console.WriteLine(String.Format("Querying {0} computer(s).", computers.Count));
                        foreach (string c in computers)
                        {
                            Thread t = new Thread(() =>
                            {
                                DumpLocalAdminGroups(c);
                            });
                            t.SetApartmentState(ApartmentState.STA);
                            t.Start();
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpLocalGroup catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpremotesession")
                {
                    string query = "";
                    string properties = "name";
                    string computername = "";
                    try
                    {


                        try
                        {
                            computername = args[2];
                            DumpRemoteSession(computername);
                        }
                        catch
                        {
                            query = "(&(objectClass=computer))";
                            List<string> computers = LdapQuery(domain, query, properties, false, true);
                            Console.WriteLine(String.Format("Querying {0} computer(s).", computers.Count));
                            foreach (string c in computers)
                            {
                                Thread t = new Thread(() =>
                                {
                                    DumpRemoteSession(c);
                                });
                                t.SetApartmentState(ApartmentState.STA);
                                t.Start();
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpRemoteSession catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpwkstasession")
                {
                    string query = "";
                    string properties = "name";
                    string computername = "";
                    try
                    {


                        try
                        {
                            computername = args[2];
                            DumpWkstaSession(computername);
                        }
                        catch
                        {
                            query = "(&(objectClass=computer))";
                            List<string> computers = LdapQuery(domain, query, properties, false, true);
                            Console.WriteLine(String.Format("Querying {0} computer(s).", computers.Count));
                            foreach (string c in computers)
                            {
                                Thread t = new Thread(() =>
                                {
                                    DumpWkstaSession(c);
                                });

                                t.SetApartmentState(ApartmentState.STA);
                                t.Start();
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpRemoteSession catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumplocaladmin")
                {
                    string query = "";
                    string properties = "name";
                    string computername = "";

                    try
                    {
                        computername = "(name=*" + args[2] + "*)";
                    }
                    catch
                    {
                        computername = "";
                    }

                    try
                    {
                        query = "(&(objectClass=computer)" + computername + ")";
                        List<string> computers = LdapQuery(domain, query, properties, false, true);
                        Console.WriteLine(String.Format("Querying {0} computer(s).", computers.Count));
                        foreach (string c in computers)
                        {
                            Thread t = new Thread(() =>
                            {
                                Console.WriteLine("\nComputer {0}\n------------------------", c);
                                DumpLocalAdminMembers(c, "Administrators");
                            });
                            t.SetApartmentState(ApartmentState.STA);
                            t.Start();
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpLocalAdmin catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumplapspassword")
                {
                    string query = "";
                    string properties = "name,ms-mcs-AdmPwd";
                    string computername = "";

                    try
                    {
                        computername = "(name=*" + args[2] + "*)";
                    }
                    catch
                    {
                        computername = "";
                    }

                    try
                    {
                        query = "(&(objectClass=user)" + computername + ")";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: CheckAdmin catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "checkadmin")
                {
                    string query = "";
                    string properties = "name";
                    string computername = "";

                    try
                    {
                        computername = "(name=*" + args[2] + "*)";
                    }
                    catch
                    {
                        computername = "";
                    }

                    try
                    {
                        query = "(&(objectClass=computer)" + computername + ")";
                        List<string> computers = LdapQuery(domain, query, properties, false, true);
                        Console.WriteLine(String.Format("Querying {0} computer(s).", computers.Count));
                        foreach (string c in computers)
                        {
                            Thread t = new Thread(() =>
                            {
                                CheckLocalAdminRight(c);
                            });
                            t.SetApartmentState(ApartmentState.STA);
                            t.Start();
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: CheckAdmin catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumptrust")
                {
                    Console.WriteLine("Domain Trust\n----------------------");
                    Domain currentDomain = Domain.GetCurrentDomain();
                    foreach (TrustRelationshipInformation d in currentDomain.GetAllTrustRelationships())
                    {
                        Console.WriteLine(String.Format("{0} <- ({1}){2} -> {3}", d.SourceName, d.TrustType, d.TrustDirection, d.TargetName));
                    }

                    Console.WriteLine("\nForest Trust\n----------------------");
                    Forest forest = Forest.GetCurrentForest();
                    foreach (TrustRelationshipInformation f in forest.GetAllTrustRelationships())
                    {
                        Console.WriteLine(String.Format("{0} <- ({1}){2} -> {3}", f.SourceName, f.TrustType, f.TrustDirection, f.TargetName));
                    }
                }
                else if (option == "dumpuser")
                {
                    string query = "";
                    string properties = "name,givenname,displayname,samaccountname,objectsid,adspath,distinguishedname,memberof,ou,mail,proxyaddresses,lastlogon,pwdlastset,mobile,streetaddress,co,title,department,description,comment,badpwdcount,objectcategory,userpassword,scriptpath,managedby,managedobjects";
                    try
                    {
                        query = "(&(objectClass=user)(samaccountname=*" + args[2] + "*))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpUser required a user argument");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpusersemail")
                {
                    string query = "";
                    string properties = "name,samaccountname,mail";
                    try
                    {
                        query = "(&(objectClass=user))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpUsersEmail catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpuserpassword")
                {
                    string query = "";
                    string properties = "name,samaccountname,userpassword";
                    try
                    {
                        query = "(&(objectClass=user))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpUserPassword catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpallcomputers")
                {
                    string query = "";
                    string properties = "name,displayname,operatingsystem,description,objectsid,adspath,objectcategory,serviceprincipalname,distinguishedname,cn,lastlogon,managedby,managedobjects";
                    try
                    {
                        query = "(&(objectClass=computer))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpAllComputers catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpcomputer")
                {
                    string query = "";
                    string properties = "name,displayname,operatingsystem,description,adspath,objectsid,objectcategory,serviceprincipalname,distinguishedname,cn,lastlogon,managedby,managedobjects";
                    try
                    {
                        query = "(&(objectClass=computer)(name=*" + args[2] + "))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpComputer required a computer name argument");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpallgroups")
                {
                    string query = "";
                    string properties = "name,adspath,distinguishedname,objectsid,member,memberof";
                    try
                    {
                        query = "(&(objectClass=group))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpAllGroups required a computer name argument");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpgroup")
                {
                    string query = "";
                    string properties = "name,adspath,distinguishedname,objectsid,member,memberof";
                    try
                    {
                        query = "(&(objectClass=group)(name=*" + args[2] + "))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpGroup required a group name argument");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumpcertificatetemplates")
                {
                    string query = "";
                    string properties = "name";
                    try
                    {
                        Console.WriteLine("CA Name is:");
                        query = "(&(!name=AIA))";
                        LdapQuery(domain, query, properties, true, false, "LDAP://CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,DC=");

                        properties = "name,displayName,distinguishedName,msPKI-Cert-Template-OID,msPKI-Enrollment-Flag,pKIExtendedKeyUsage,msPKI-Certificate-Name-Flag";
                        query = "(&(name=*))";
                        LdapQuery(domain, query, properties, true, false, "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpCertificateTemplates catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumppasswordpolicy")
                {
                    string query = "";
                    string properties = "name,distinguishedName,msDS-MinimumPasswordLength,msDS-PasswordHistoryLength,msDS-PasswordComplexityEnabled,msDS-PasswordReversibleEncryptionEnabled,msDS-LockoutThreshold,msDS-PasswordSettingsPrecedence";
                    try
                    {
                        query = "(&(name=ms-DS-Password-Settings))";
                        LdapQuery(domain, query, properties, true, false, "LDAP://CN=Schema,CN=Configuration,DC=");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpPasswordPolicy catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "dumppwdlastset")
                {
                    // Based on https://www.trustedsec.com/blog/targeted-active-directory-host-enumeration/
                    string query = "";
                    string properties = "name,givenname,displayname,samaccountname,adspath,distinguishedname,memberof,ou,mail,proxyaddresses,lastlogon,pwdlastset,mobile,streetaddress,co,title,department,description,comment,badpwdcount,objectcategory,userpassword,scriptpath";
                    var date = DateTime.Today.AddDays(-(DateTime.Today.Day + 90));
                    long dateUtc = date.ToFileTimeUtc();
                    try
                    {
                        query = "(&(objectCategory=computer)(pwdlastset>=" + dateUtc.ToString() + ")(operatingSystem=*windows*))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpPasswordPolicy catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "checkmanaged")
                {
                    /*
                    */
                    if (ListFilesSearchForManaged("\\\\" + domain + "\\SYSVOL", verboseDebug))
                    {
                        string query = "";
                        string properties = "managedobjects,samaccountname";
                        Console.WriteLine("Users that have a managedobjects attribute");
                        try
                        {
                            query = "(&(objectClass=user))";
                            LdapQuery(domain, query, properties, false);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("ERROR: checkmanaged on users catched an unexpected exception");
                            ShowDebug(e, verboseDebug);
                        }
                        Console.WriteLine("Computers that have a managedby attribute");
                        properties = "managedby,name";
                        try
                        {
                            query = "(&(objectClass=computer))";
                            LdapQuery(domain, query, properties, false);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("ERROR: checkmanaged on computers catched an unexpected exception");
                            ShowDebug(e, verboseDebug);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Managedby GPO not found");
                    }
                }
                else if (option == "dumplastlogon")
                {
                    // Based on https://www.trustedsec.com/blog/targeted-active-directory-host-enumeration/
                    string query = "";
                    string properties = "name,givenname,displayname,samaccountname,adspath,objectsid,distinguishedname,memberof,ou,mail,proxyaddresses,lastlogon,pwdlastset,mobile,streetaddress,co,title,department,description,comment,badpwdcount,objectcategory,userpassword,scriptpath";
                    var date = DateTime.Today.AddDays(-(DateTime.Today.Day + 90));
                    long dateUtc = date.ToFileTimeUtc();
                    try
                    {
                        query = "(&(objectCategory=computer)(lastLogon>=" + dateUtc.ToString() + ")(operatingSystem=*windows*))";
                        LdapQuery(domain, query, properties);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("ERROR: DumpPasswordPolicy catched an unexpected exception");
                        ShowDebug(e, verboseDebug);
                    }
                }
                else if (option == "getshare")
                {
                    string hostname = args[1];
                    string username = "";
                    string password = "";

                    if (args.Length > 2)
                    {
                        username = args[2].Split('\\')[1];
                        domain = args[2].Split('\\')[0];
                        password = args[3];
                        const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
                        const int LOGON32_PROVIDER_DEFAULT = 0;
                        IntPtr phToken = IntPtr.Zero;

                        bool bResult = false;
                        if (username != null)
                        {
                            bResult = LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref phToken);
                            if (!bResult)
                            {
                                Console.WriteLine("Error: " + GetLastError());
                            }
                        }
                        bResult = ImpersonateLoggedOnUser(phToken);
                        if (!bResult)
                        {
                            Console.WriteLine("Error: " + GetLastError());
                        }
                    }

                    int entriesread = 0;
                    int totalentries = 0;
                    int resume_handle = 0;

                    int structSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
                    IntPtr bufPtr = IntPtr.Zero;

                    int ret = NetShareEnum(hostname, 1, ref bufPtr, 0xFFFFFFFF, ref entriesread, ref totalentries, ref resume_handle);

                    if (ret == 0)
                    {
                        IntPtr currentPtr = bufPtr;

                        for (int i = 0; i < entriesread; i++)
                        {
                            SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                            Console.WriteLine("\\\\{0}\\{1}", hostname, shi1);
                            currentPtr += structSize;
                        }

                    }

                }
                else if (option == "getservice")
                {

                    string hostname = args[1];
                    string username = "";
                    string password = "";

                    if (args.Length > 2)
                    {
                        username = args[2].Split('\\')[1];
                        domain = args[2].Split('\\')[0];
                        password = args[3];
                        const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
                        const int LOGON32_PROVIDER_DEFAULT = 0;
                        IntPtr phToken = IntPtr.Zero;

                        bool bResult = false;
                        if (username != null)
                        {
                            bResult = LogonUser(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, ref phToken);
                            if (!bResult)
                            {
                                Console.WriteLine("Error: " + GetLastError());
                            }
                        }
                        bResult = ImpersonateLoggedOnUser(phToken);
                        if (!bResult)
                        {
                            Console.WriteLine("Error: " + GetLastError());
                        }
                    }

                    ServiceController[] services = ServiceController.GetServices(hostname);

                    foreach (ServiceController service in services)
                    {
                        Console.WriteLine("{0}:{1}", service.ServiceName, service.Status);
                    }

                }
                else
                {
                    Console.WriteLine("Invalid argument: {0} not found", option);
                }
            }
            else
            {
                if (args.Length == 1)
                {
                    if (args[0] == "set")
                    {
                        foreach (DictionaryEntry de in Environment.GetEnvironmentVariables())
                        {
                            Console.WriteLine("{0}={1}", de.Key, de.Value);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("ERROR: missing arguments");
                    Console.WriteLine("Usage: {0} options domain [arguments]", System.Reflection.Assembly.GetExecutingAssembly().Location);
                }
            }
        }
    }

    // Thanks stackoverflow for this parser.
    class SDDLParser
    {
        static private Dictionary<string, string> ACE_Types = null;
        static private Dictionary<string, string> ACE_Flags = null;
        static private Dictionary<string, string> Permissions = null;
        static private Dictionary<string, string> Trustee = null;

        private static void Initialize()
        {
            ACE_Types = new Dictionary<string, string>();
            ACE_Flags = new Dictionary<string, string>();
            Permissions = new Dictionary<string, string>();
            Trustee = new Dictionary<string, string>();
            #region Add ACE_Types
            ACE_Types.Add("A", "Access Allowed");
            ACE_Types.Add("D", "Access Denied");
            ACE_Types.Add("OA", "Object Access Allowed");
            ACE_Types.Add("OD", "Object Access Denied");
            ACE_Types.Add("AU", "System Audit");
            ACE_Types.Add("AL", "System Alarm");
            ACE_Types.Add("OU", "Object System Audit");
            ACE_Types.Add("OL", "Object System Alarm");
            #endregion
            #region Add ACE_Flags
            ACE_Flags.Add("CI", "Container Inherit");
            ACE_Flags.Add("OI", "Object Inherit");
            ACE_Flags.Add("NP", "No Propagate");
            ACE_Flags.Add("IO", "Inheritance Only");
            ACE_Flags.Add("ID", "Inherited");
            ACE_Flags.Add("SA", "Successful Access Audit");
            ACE_Flags.Add("FA", "Failed Access Audit");
            #endregion
            #region Add Permissions
            #region Generic Access Rights
            Permissions.Add("GA", "Generic All");
            Permissions.Add("GR", "Generic Read");
            Permissions.Add("GW", "Generic Write");
            Permissions.Add("GX", "Generic Execute");
            #endregion
            #region Directory Access Rights
            Permissions.Add("RC", "Read Permissions");
            Permissions.Add("SD", "Delete");
            Permissions.Add("WD", "Modify Permissions");
            Permissions.Add("WO", "Modify Owner");
            Permissions.Add("RP", "Read All Properties");
            Permissions.Add("WP", "Write All Properties");
            Permissions.Add("CC", "Create All Child Objects");
            Permissions.Add("DC", "Delete All Child Objects");
            Permissions.Add("LC", "List Contents");
            Permissions.Add("SW", "All Validated Writes");
            Permissions.Add("LO", "List Object");
            Permissions.Add("DT", "Delete Subtree");
            Permissions.Add("CR", "All Extended Rights");
            #endregion
            #region File Access Rights
            Permissions.Add("FA", "File All Access");
            Permissions.Add("FR", "File Generic Read");
            Permissions.Add("FW", "File Generic Write");
            Permissions.Add("FX", "File Generic Execute");
            #endregion
            #region Registry Key Access Rights
            Permissions.Add("KA", "Key All Access");
            Permissions.Add("KR", "Key Read");
            Permissions.Add("KW", "Key Write");
            Permissions.Add("KX", "Key Execute");
            #endregion
            #endregion
            #region Add Trustee's
            Trustee.Add("AO", "Account Operators");
            Trustee.Add("RU", "Alias to allow previous Windows 2000");
            Trustee.Add("AN", "Anonymous Logon");
            Trustee.Add("AU", "Authenticated Users");
            Trustee.Add("BA", "Built-in Administrators");
            Trustee.Add("BG", "Built in Guests");
            Trustee.Add("BO", "Backup Operators");
            Trustee.Add("BU", "Built-in Users");
            Trustee.Add("CA", "Certificate Server Administrators");
            Trustee.Add("CG", "Creator Group");
            Trustee.Add("CO", "Creator Owner");
            Trustee.Add("DA", "Domain Administrators");
            Trustee.Add("DC", "Domain Computers");
            Trustee.Add("DD", "Domain Controllers");
            Trustee.Add("DG", "Domain Guests");
            Trustee.Add("DU", "Domain Users");
            Trustee.Add("EA", "Enterprise Administrators");
            Trustee.Add("ED", "Enterprise Domain Controllers");
            Trustee.Add("WD", "Everyone");
            Trustee.Add("PA", "Group Policy Administrators");
            Trustee.Add("IU", "Interactively logged-on user");
            Trustee.Add("LA", "Local Administrator");
            Trustee.Add("LG", "Local Guest");
            Trustee.Add("LS", "Local Service Account");
            Trustee.Add("SY", "Local System");
            Trustee.Add("NU", "Network Logon User");
            Trustee.Add("NO", "Network Configuration Operators");
            Trustee.Add("NS", "Network Service Account");
            Trustee.Add("PO", "Printer Operators");
            Trustee.Add("PS", "Self");
            Trustee.Add("PU", "Power Users");
            Trustee.Add("RS", "RAS Servers group");
            Trustee.Add("RD", "Terminal Server Users");
            Trustee.Add("RE", "Replicator");
            Trustee.Add("RC", "Restricted Code");
            Trustee.Add("SA", "Schema Administrators");
            Trustee.Add("SO", "Server Operators");
            Trustee.Add("SU", "Service Logon User");
            #endregion
        }

        private static string friendlyTrusteeName(string trustee)
        {
            if (Trustee.ContainsKey(trustee))
            {
                return Trustee[trustee];
            }
            else
            {
                try
                {
                    System.Security.Principal.SecurityIdentifier sid = new System.Security.Principal.SecurityIdentifier(trustee);
                    return sid.Translate(typeof(System.Security.Principal.NTAccount)).ToString();
                }
                catch (Exception)
                {
                    return trustee;
                }
            }
        }

        private static string doParse(string subSDDL, string Separator, string Separator2)
        {
            string retval = "";
            char type = subSDDL.ToCharArray()[0];
            if (type == 'O')
            {
                string owner = subSDDL.Substring(2);
                return "Owner: " + friendlyTrusteeName(owner) + Separator;
            }
            else if (type == 'G')
            {
                string group = subSDDL.Substring(2);
                return "Group: " + friendlyTrusteeName(group) + Separator;
            }
            else if ((type == 'D') || (type == 'S'))
            {
                if (type == 'D')
                {
                    retval += "DACL" + Separator;
                }
                else
                {
                    retval += "SACL" + Separator;
                }
                string[] sections = subSDDL.Split('(');
                for (int count = 1; count < sections.Length; count++)
                {
                    retval += "------------" + Separator;
                    string[] parts = sections[count].TrimEnd(')').Split(';');
                    retval += "";
                    if (ACE_Types.ContainsKey(parts[0]))
                    {
                        retval += Separator2 + "Type: " + ACE_Types[parts[0]] + Separator;
                    }
                    if (ACE_Flags.ContainsKey(parts[1]))
                    {
                        retval += Separator2 + "Inheritance: " + ACE_Flags[parts[1]] + Separator;
                    }
                    for (int count2 = 0; count2 < parts[2].Length; count2 += 2)
                    {
                        string perm = parts[2].Substring(count2, 2);
                        if (Permissions.ContainsKey(perm))
                        {
                            if (count2 == 0)
                            {
                                retval += Separator2 + "Permissions: " + Permissions[perm];
                            }
                            else
                            {
                                retval += "|" + Permissions[perm];
                            }
                        }
                    }
                    retval += Separator;
                    retval += Separator2 + "Trustee: " + friendlyTrusteeName(parts[5]) + Separator;
                }
            }
            return retval;
        }

        public static string Parse(string SDDL)
        {
            return Parse(SDDL, "\r\n", "");
        }

        public static string Parse(string SDDL, string Separator, string Separator2)
        {
            string retval = "";
            if (ACE_Types == null)
            {
                Initialize();
            }
            int startindex = 0;
            int nextindex = 0;
            int first = 0;
            string section;
            while (true)
            {
                first = SDDL.IndexOf(':', nextindex) - 1;
                startindex = nextindex;
                if (first < 0)
                {
                    break;
                }
                if (first != 0)
                {
                    section = SDDL.Substring(startindex - 2, first - startindex + 2);
                    retval += doParse(section, Separator, Separator2);
                }
                nextindex = first + 2;
            }
            section = SDDL.Substring(startindex - 2);
            retval += doParse(section, Separator, Separator2);
            return retval;
        }
    }
}
