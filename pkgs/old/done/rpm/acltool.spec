Name:		acltool
Version:	1.16.3
Release:	1%{?dist}
Summary:	ACL management tool

License:	BSD
URL:		https://github.com/ptrrkssn/acltool
Source0:	https://codeload.github.com/ptrrkssn/%{name}/tar.gz/v%{version}?dummy=/%{name}-%{version}.tar.gz
Prefix:		%{_prefix}
BuildRoot:	%{_tmppath}/%{name}-root

%description
This is a tool to manage NFSv4/ZFS (also known as Extended on MacOS) ACLs.
That is listing, creating, editing, searching, stripping, sorting and
removing redundant entries and more.

%prep
%setup -q -n %{name}-%{version}

%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%{_prefix} --mandir=%{_mandir} --libdir=%{_libdir}
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr "$RPM_BUILD_ROOT"
make DESTDIR="$RPM_BUILD_ROOT" install

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -fr "$RPM_BUILD_ROOT"

%files
%defattr(-,root,root)
%doc README LICENSE TODO
%{_bindir}/acltool
%{_bindir}/sac
%{_bindir}/lac
%{_bindir}/edac
%{_mandir}/man1/acltool.1.gz
%{_mandir}/man1/lac.1.gz
%{_mandir}/man1/sac.1.gz
%{_mandir}/man1/edac.1.gz

