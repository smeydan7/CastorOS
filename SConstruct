import sys
import os
import shutil
import multiprocessing
import SCons.Util

## Configuration

opts = Variables('Local.sc')

opts.AddVariables(
    ("CC", "C Compiler"),
    ("AS", "Assembler"),
    ("LINK", "Linker"),
    ("AR", "Archiver"),
    ("RANLIB", "Archiver Indexer"),
    ("BUILDTYPE", "Build type (RELEASE, DEBUG, or PERF)", "RELEASE"),
    ("VERBOSE", "Show full build information (0 or 1)", "0"),
    ("STRICT", "Strict error checking (0 or 1)", "0"),
    ("NUMCPUS", "Number of CPUs to use for build (0 means auto).", "0"),
    ("WITH_GPROF", "Include gprof profiling (0 or 1).", "0"),
    ("PREFIX", "Installation target directory.", "#pxelinux"),
    ("ARCH", "Target Architecture", "amd64"),
    ("BOOTDISK", "Build boot disk (0 or 1)", "1"),
    ("BOOTDISK_SIZE", "Boot disk size", "128")
)

env = Environment(options = opts,
                  tools = ['default', 'compilation_db'],
                  ENV = os.environ)
Help(opts.GenerateHelpText(env))

# Copy environment variables
if 'CC' in os.environ:
    env["CC"] = os.getenv('CC')
if 'AS' in os.environ:
    env["AS"] = os.getenv('AS')
if 'LD' in os.environ:
    env["LINK"] = os.getenv('LD')
if 'AR' in os.environ:
    env["AR"] = os.getenv('AR')
if 'RANLIB' in os.environ:
    env["RANLIB"] = os.getenv('RANLIB')
if 'CFLAGS' in os.environ:
    env.Append(CCFLAGS = SCons.Util.CLVar(os.environ['CFLAGS']))
if 'CPPFLAGS' in os.environ:
    env.Append(CPPFLAGS = SCons.Util.CLVar(os.environ['CPPFLAGS']))
if 'LDFLAGS' in os.environ:
    env.Append(LINKFLAGS = SCons.Util.CLVar(os.environ['LDFLAGS']))

toolenv = env.Clone()

env.Append(CFLAGS = [ "-Wshadow", "-Wno-typedef-redefinition" ])
env.Append(CPPFLAGS = [ "-target", "x86_64-freebsd-freebsd-elf",
                        "-fno-builtin", "-fno-stack-protector",
                        "-fno-optimize-sibling-calls" ])
env.Append(LINKFLAGS = [ "-no-pie" ])

if (env["STRICT"] == "1"):
    env.Append(CPPFLAGS = [ "-Wformat=2", "-Wmissing-format-attribute",
                            "-Wthread-safety", "-Wwrite-strings" ])                        

if env["WITH_GPROF"] == "1":
    env.Append(CPPFLAGS = [ "-pg" ])
    env.Append(LINKFLAGS = [ "-pg" ])

env.Append(CPPFLAGS = "-DBUILDTYPE=" + env["BUILDTYPE"])
if env["BUILDTYPE"] == "DEBUG":
    env.Append(CPPFLAGS = [ "-g", "-DDEBUG", "-Wall", 
        "-Wno-deprecated-declarations" ])
    env.Append(LINKFLAGS = [ "-g" ])
elif env["BUILDTYPE"] == "PERF":
    env.Append(CPPFLAGS = [ "-g", "-DNDEBUG", "-Wall", "-O2"])
    env.Append(LDFLAGS = [ "-g" ])
elif env["BUILDTYPE"] == "RELEASE":
    env.Append(CPPFLAGS = ["-DNDEBUG", "-Wall", "-O2"])
else:
    print("Error BUILDTYPE must be RELEASE or DEBUG")
    sys.exit(-1)

if env["ARCH"] != "amd64":
    print("Unsupported architecture: " + env["ARCH"])
    sys.exit(-1)

try:
    hf = open(".git/HEAD", 'r')
    head = hf.read()
    if head.startswith("ref: "):
        if head.endswith("\n"):
            head = head[0:-1]
        with open(".git/" + head[5:]) as bf:
            branch = bf.read()
            if branch.endswith("\n"):
                branch = branch[0:-1]
            env.Append(CPPFLAGS = [ "-DGIT_VERSION=\\\"" + branch + "\\\""])
except IOError:
    pass

if env["VERBOSE"] == "0":
    env["CCCOMSTR"] = "Compiling $SOURCE"
    env["SHCCCOMSTR"] = "Compiling $SOURCE"
    env["ARCOMSTR"] = "Creating library $TARGET"
    env["RANLIBCOMSTR"] = "Indexing library $TARGET"
    env["LINKCOMSTR"] = "Linking $TARGET"
    env["ASCOMSTR"] = "Assembling $TARGET"
    env["ASPPCOMSTR"] = "Assembling $TARGET"
    env["ARCOMSTR"] = "Archiving $TARGET"
    env["RANLIBCOMSTR"] = "Indexing $TARGET"

def GetNumCPUs(env):
    if env["NUMCPUS"] != "0":
        return int(env["NUMCPUS"])
    return 2*multiprocessing.cpu_count()

env.SetOption('num_jobs', GetNumCPUs(env))

def CopyTree(dst, src, env):
    def DirCopyHelper(src, dst):
        for f in os.listdir(src):
            srcPath = os.path.join(src, f)
            dstPath = os.path.join(dst, f)
            if f.startswith("."):
                # Ignore hidden files
                pass
            elif os.path.isdir(srcPath):
                if not os.path.exists(dstPath):
                    os.makedirs(dstPath)
                DirCopyHelper(srcPath, dstPath)
            else:
                env.Command(dstPath, srcPath, Copy("$TARGET", "$SOURCE"))
            if (not os.path.exists(dst)):
                os.makedirs(dst)
    DirCopyHelper(src, dst)

# XXX: Hack to support clang static analyzer
def CheckFailed():
    if os.getenv('CCC_ANALYZER_OUTPUT_FORMAT') != None:
        return
    Exit(1)

# Configuration
conf = env.Configure()

if not conf.CheckCC():
    print('Your C compiler and/or environment is incorrectly configured.')
    CheckFailed()

if not env["CCVERSION"].startswith("15."):
    print('Only Clang 15 is supported')
    print('You are running: ' + env["CCVERSION"])
    CheckFailed()

conf.Finish()

Export('env')
Export('toolenv')


# Program start/end
env["CRTBEGIN"] = [ "#build/lib/libc/crti.o", "#build/lib/libc/crt1.o" ]
env["CRTEND"] = [ "#build/lib/libc/crtn.o" ]

# Debugging Tools

# Create include tree
CopyTree('build/include', 'include', env)
CopyTree('build/include/sys', 'sys/include', env)
CopyTree('build/include/machine', 'sys/' + env['ARCH'] + '/include', env)
#CopyTree('build/include/', 'lib/liblwip/src/include', env)

# Build Targets
SConscript('sys/SConscript', variant_dir='build/sys')
SConscript('lib/libc/SConscript', variant_dir='build/lib/libc')
#SConscript('lib/liblwip/SConscript', variant_dir='build/lib/liblwip')
SConscript('bin/cat/SConscript', variant_dir='build/bin/cat')
SConscript('bin/date/SConscript', variant_dir='build/bin/date')
SConscript('bin/echo/SConscript', variant_dir='build/bin/echo')
SConscript('bin/ethdump/SConscript', variant_dir='build/bin/ethdump')
SConscript('bin/ethinject/SConscript', variant_dir='build/bin/ethinject')
SConscript('bin/false/SConscript', variant_dir='build/bin/false')
SConscript('bin/ls/SConscript', variant_dir='build/bin/ls')
SConscript('bin/shell/SConscript', variant_dir='build/bin/shell')
SConscript('bin/stat/SConscript', variant_dir='build/bin/stat')
SConscript('bin/true/SConscript', variant_dir='build/bin/true')
SConscript('sbin/ifconfig/SConscript', variant_dir='build/sbin/ifconfig')
SConscript('sbin/init/SConscript', variant_dir='build/sbin/init')
SConscript('sbin/sysctl/SConscript', variant_dir='build/sbin/sysctl')
SConscript('tests/SConscript', variant_dir='build/tests')

# Build Tools
env["TOOLCHAINBUILD"] = "TRUE"
env["CC"] = "cc"
env["LINK"] = "cc"
SConscript('sbin/newfs_o2fs/SConscript', variant_dir='build/tools/newfs_o2fs')

env.CompilationDatabase()

# Install Targets
env.Install('$PREFIX/','build/sys/castor')
env.Alias('install','$PREFIX')

# Boot Disk Target
if env["BOOTDISK"] == "1":
    newfs = Builder(action = 'build/tools/newfs_o2fs/newfs_o2fs -s $BOOTDISK_SIZE -m $SOURCE $TARGET')
    env.Append(BUILDERS = {'BuildImage' : newfs})
    bootdisk = env.BuildImage('#build/bootdisk.img', '#release/bootdisk.manifest')
    Depends(bootdisk, "#build/tools/newfs_o2fs/newfs_o2fs")
    Depends(bootdisk, "#build/bin/cat/cat")
    Depends(bootdisk, "#build/bin/date/date")
    Depends(bootdisk, "#build/bin/echo/echo")
    Depends(bootdisk, "#build/bin/ethdump/ethdump")
    Depends(bootdisk, "#build/bin/ethinject/ethinject")
    Depends(bootdisk, "#build/bin/false/false")
    Depends(bootdisk, "#build/bin/ls/ls")
    Depends(bootdisk, "#build/bin/shell/shell")
    Depends(bootdisk, "#build/bin/stat/stat")
    Depends(bootdisk, "#build/bin/true/true")
    Depends(bootdisk, "#build/sbin/ifconfig/ifconfig")
    Depends(bootdisk, "#build/sbin/init/init")
    Depends(bootdisk, "#build/sbin/sysctl/sysctl")
    Depends(bootdisk, "#build/sys/castor")
    #Depends(bootdisk, "#build/tests/lwiptest")
    Depends(bootdisk, "#build/tests/writetest")
    Depends(bootdisk, "#build/tests/fiotest")
    Depends(bootdisk, "#build/tests/pthreadtest")
    Depends(bootdisk, "#build/tests/spawnanytest")
    Depends(bootdisk, "#build/tests/spawnmultipletest")
    Depends(bootdisk, "#build/tests/spawnsingletest")
    Depends(bootdisk, "#build/tests/threadtest")
    env.Alias('bootdisk', '#build/bootdisk.img')
    env.Install('$PREFIX/','#build/bootdisk.img')

