%define url $URL$

%define name procprotect
%define version 0.1
%define taglevel 1

%define release %{taglevel}%{?pldistro:.%{pldistro}}%{?date:.%{date}}

Vendor: PlanetLab
Packager: PlanetLab Central <support@planet-lab.org>
Distribution: PlanetLab %{plrelease}
URL: %(echo %{url} | cut -d ' ' -f 2)

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
make -C /lib/modules/`ls /lib/modules | head -1`/build M=$PWD modules

%install
mkdir -p $RPM_BUILD_ROOT/lib/modules/`ls /lib/modules | head -1`/kernel/net/procprotect
cp procprotect.ko $RPM_BUILD_ROOT/lib/modules/`ls /lib/modules | head -1`/kernel/net/procprotect

%clean
rm -rf $RPM_BUILD_ROOT

%files
/lib

%post

%postun

%changelog
