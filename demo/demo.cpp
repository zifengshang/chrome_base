// test.cpp : Defines the entry point for the console application.
//

#include <windows.h>

#include "base\at_exit.h"
#include "base\bind.h"
#include "base\files\file_path.h"
#include "base\files\file_util.h"
#include "base\memory\weak_ptr.h"
#include "base\process\process_handle.h"
#include "base\run_loop.h"
#include "base\strings\string_util.h"
#include "base\strings\string16.h"
#include "base\strings\utf_string_conversions.h"
#include "base\threading\thread.h"
#include "base\threading\thread_task_runner_handle.h"
#include "base\win\registry.h"
#include "ntapi\ntapi.h"

#pragma comment(lib, "version")
#pragma comment(lib, "Dbghelp")
#pragma comment(lib, "Winmm")
#pragma comment(lib, "Ws2_32")

#pragma comment(lib, "base")
#pragma comment(lib, "modp_b64")

using namespace base;

void OnTimer() {
  static int count = 0;
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
    FROM_HERE,
    base::Bind(OnTimer),
    base::TimeDelta::FromMilliseconds(1000));
  wprintf_s(L"io thread, id:%d count:%d\n",
    GetCurrentThreadId(), count++);
}


class Test : public base::SupportsWeakPtr<Test> {
public:
  int iCount_ = 0;

  void OnTimer() {
    if (++iCount_ == 5) {
      MessageLoop* loop = MessageLoop::current();
      if (loop) {
        loop->QuitNow();
        wprintf_s(L"main thread, id:%d count:%d will quit\n",
          GetCurrentThreadId(), iCount_);
      }
    } else {
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
        FROM_HERE,
        base::Bind(&Test::OnTimer, AsWeakPtr()),
        base::TimeDelta::FromMilliseconds(1000));
      wprintf_s(L"main thread, id:%d count:%d\n",
        GetCurrentThreadId(), iCount_);
    }
  }
};


bool EnablePrivileges() {

  bool rtn = false;
  HANDLE token = NULL;

  if (OpenProcessToken(GetCurrentProcessHandle(),
    TOKEN_ADJUST_PRIVILEGES, &token)) {

    CHAR privilegesBuffer[FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) + sizeof(LUID_AND_ATTRIBUTES) * 8];

    PTOKEN_PRIVILEGES privileges;
    privileges = (PTOKEN_PRIVILEGES)privilegesBuffer;
    privileges->PrivilegeCount = 8;

    for (ULONG i = 0; i < privileges->PrivilegeCount; i++) {
      privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
      privileges->Privileges[i].Luid.HighPart = 0;
    }

    privileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
    privileges->Privileges[1].Luid.LowPart = SE_INC_BASE_PRIORITY_PRIVILEGE;
    privileges->Privileges[2].Luid.LowPart = SE_INC_WORKING_SET_PRIVILEGE;
    privileges->Privileges[3].Luid.LowPart = SE_LOAD_DRIVER_PRIVILEGE;
    privileges->Privileges[4].Luid.LowPart = SE_PROF_SINGLE_PROCESS_PRIVILEGE;
    privileges->Privileges[5].Luid.LowPart = SE_RESTORE_PRIVILEGE;
    privileges->Privileges[6].Luid.LowPart = SE_SHUTDOWN_PRIVILEGE;
    privileges->Privileges[7].Luid.LowPart = SE_TAKE_OWNERSHIP_PRIVILEGE;

    rtn = !!AdjustTokenPrivileges(token, FALSE, privileges, 0, NULL,NULL);

    CloseHandle(token);
  }
  return rtn;
}

int main()
{
  base::AtExitManager exit_mgr;
  
  EnablePrivileges();

  NTSTATUS status = 0;
  {
    base::win::ScopedHandle handle(OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
      FALSE, 2012));
    
    IO_PRIORITY_HINT priority = IoPriorityVeryLow;
    status = NtQueryInformationProcess(
      handle.Get(), ProcessIoPriority, &priority,
      sizeof(IO_PRIORITY_HINT), NULL);

    priority = IoPriorityLow;
    status = NtSetInformationProcess(
        handle.Get(), ProcessIoPriority,
        &priority, sizeof(IO_PRIORITY_HINT));
  }

  {
    base::string16 a = L"你好";
    std::string b = base::WideToUTF8(a);
    bool rtn = base::StartsWith(L"testtest", L"te", false);
  }

  {
    std::wstring value;
    base::win::RegKey reg(HKEY_CURRENT_USER, L"tencent\\qqbrowser", KEY_READ | KEY_WRITE);
    if (reg.Valid()) {
      reg.ReadValue(L"caver", &value);
    }
  }

  {
    bool rtn = false;
    base::FilePath path(L"c:\\a.txt");
    base::FilePath file = path.RemoveExtension();

    std::wstring ext = path.Extension();
    file = path.BaseName();
    file = path.DirName();

    base::FilePath t = file.Append(base::FilePath(L"b"));
    if (!base::DirectoryExists(t)) {
      rtn = base::CreateDirectory(t);
    }

    base::FilePath temp;
    rtn = base::CreateTemporaryFile(&temp);
    if (base::PathExists(temp)) {
      base::WriteFile(temp, "test", 4);
    }
  }
  
  {
    class MainThread : public Thread {
    public:
      MainThread(const std::string& name,
        MessageLoop* message_loop) :
        Thread(name) {
        SetMessageLoop(message_loop);
      }
    };

    base::Thread::Options options;
    options.message_loop_type = base::MessageLoop::TYPE_IO;
    std::unique_ptr<base::Thread> io_thread(new base::Thread("io thread"));
    io_thread->StartWithOptions(options);
    io_thread->task_runner()->PostDelayedTask(
      FROM_HERE,
      base::Bind(OnTimer),
      base::TimeDelta::FromMilliseconds(800));

    std::unique_ptr<base::MessageLoop> main_message_loop(new base::MessageLoopForUI);
    std::unique_ptr<base::Thread> main_thread(
      new MainThread("main thread", main_message_loop.get()));

    std::unique_ptr<Test> t(new Test);
    main_thread->task_runner()->PostDelayedTask(
      FROM_HERE,
      base::Bind(&Test::OnTimer, t->AsWeakPtr()),
      base::TimeDelta::FromMilliseconds(1000));
    //t.reset();

    base::RunLoop run_loop;
    run_loop.Run();

    t.reset();
    io_thread.reset();
    main_thread.reset();
    main_message_loop.reset();
  }

  //system("pause");

  return 0;
}

