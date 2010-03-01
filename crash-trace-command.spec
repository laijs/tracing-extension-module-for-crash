#
# crash core analysis suite
#
Summary: trace extension module for the crash utility
Name: crash-trace-command
Version: 1.0
Release: 1
License: GPLv2
Group: Development/Debuggers
Source: %{name}-%{version}.tar.gz
URL: http://people.redhat.com/anderson/extensions/trace.c
Vendor: Fujitsu Limited
Packager: Lai Jiangshan <laijs@cn.fujitsu.com>
ExclusiveOS: Linux
ExclusiveArch: x86_64 i386 ppc64 ia64 s390 s390x
Buildroot: %{_tmppath}/%{name}-root
BuildRequires: crash-devel zlib-devel

%description
Command for reading ftrace data from a dumpfile.

%prep
%setup -n %{name}-%{version}

%build
make

%install
mkdir -p %{buildroot}%{_libdir}/crash/extensions/
cp %{_builddir}/%{name}-%{version}/trace.so %{buildroot}%{_libdir}/crash/extensions/

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%{_libdir}/crash/extensions/trace.so
%doc COPYING

%changelog
* Fri Sep 25 2009  Dave Anderson <anderson@redhat.com>
- Initial crash-trace-command package

