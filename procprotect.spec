%define name procprotect
%define version 0.4
%define taglevel 3

### legacy from locally-built kernels, used to define these
# kernel_release : 1.fc16  (24 is then the planetlab taglevel)
# kernel_version : 3.3.7
# kernel_arch :    i686 | x86_64

# compute this with "rpm -q --qf .. kernel-devel" when with the stock kernel
# this line below
#%define module_release %( rpm -q --qf "%{version}" kernel-headers )
# causes recursive macro definition no matter how much you quote
%define percent %
%define braop \{
%define bracl \}
%define kernel_version %( rpm -q --qf %{percent}%{braop}version%{bracl} kernel-headers )
%define kernel_release %( rpm -q --qf %{percent}%{braop}release%{bracl} kernel-headers )
%define kernel_arch %( rpm -q --qf %{percent}%{braop}arch%{bracl} kernel-headers )

# this is getting really a lot of stuff, could be made simpler probably
%define release %{kernel_version}.%{kernel_release}.%{taglevel}%{?pldistro:.%{pldistro}}%{?date:.%{date}}

%define kernel_id %{kernel_version}-%{kernel_release}.%{kernel_arch}
%define kernelpath /usr/src/kernels/%{kernel_id}


Vendor: PlanetLab
Packager: PlanetLab Central <support@planet-lab.org>
Distribution: PlanetLab %{plrelease}
URL: %{SCMURL}

Summary: Proc fs acls
Name: %{name}
Version: %{version}
Release: %{release}
License: GPL
Group: System Environment/Kernel
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Source0: procprotect-%{version}.tar.gz

%description
ACLs for protecting entries in the proc filesystem.

%prep 
%setup -q

%build
make -C %{kernelpath} V=1 M=$(pwd) modules

%install
install -D -m 755 procprotect.ko $RPM_BUILD_ROOT/lib/modules/%{kernel_id}/kernel/net/procprotect/procprotect.ko
install -D -m 644 procprotect.conf $RPM_BUILD_ROOT/etc/modules-load.d/procprotect.conf
install -D -m 644 procprotect.service $RPM_BUILD_ROOT/usr/lib/systemd/system/procprotect.service
install -D -m 755 procprotect.init $RPM_BUILD_ROOT/usr/sbin/procprotect.init

%clean
rm -rf $RPM_BUILD_ROOT

%files
/lib/modules/%{kernel_id}
/etc/modules-load.d/procprotect.conf
/usr/sbin/procprotect.init
/usr/lib/systemd/system/procprotect.service

%post
/sbin/depmod -a
/bin/systemctl enable procprotect.service

%postun

%changelog
* Fri Mar 21 2014 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - procprotect-0.4-3
- guarded against some hypothetically possible errors

* Wed Aug 28 2013 Sapan Bhatia <sapanb@cs.princeton.edu> - procprotect-0.4-2
- * Bug fixes that should lead to increased stability
- * Install via make and make install

* Mon Aug 19 2013 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - procprotect-0.4-1
- working version with kernels 3.10

* Tue May 21 2013 Sapan Bhatia <sapanb@cs.princeton.edu> - procprotect-0.3-4
- Compatibility with kernel 3.9

* Wed Apr 24 2013 Sapan Bhatia <sapanb@cs.princeton.edu> - procprotect-0.3-3
- - Support for arbitrating writes to entries in /proc
- - Compatibility fixes to support kernel 3.8
- - Fixed a slippery race condition that may have been responsible an for intermittent kernel crash, and was causing fedora 18 build tests to fail

* Wed Apr 24 2013 Sapan Bhatia <sapanb@cs.princeton.edu> - procprotect-0.3-2

* Thu Feb 21 2013 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - procprotect-0.3-1
- changes for kernel 3.6.2

* Mon Nov 26 2012 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - procprotect-0.1-3
- Fixed bad security loophole in write path

* Mon Jul 09 2012 Thierry Parmentelat <thierry.parmentelat@sophia.inria.fr> - procprotect-0.1-2
- module to get loaded at boot-time

