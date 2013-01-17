Name:           keyutil
Version:        0.4.0
Release:        1
Summary:        Java Key Utility
Group:          Applications/System
License:        BSD
URL:            http://code.google.com/p/java-keyutil/
Source0:        http://java-keyutil.googlecode.com/files/keyutil-%{version}.jar
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

Requires:       java

%description
Merges mutil-part PEM files (Concatenated PEM certs) and Java Keystore into new
or existing Java Keystore JKS files

%prep
cp -p %SOURCE0 .
cat > keyutil << EOF
#!/bin/sh

java -jar %{_libdir}/keyutil/keyutil-%{version}.jar \$*
EOF
%build


%install
%{__rm} -rf %{buildroot}
%{__install} -d -m 0755 %{buildroot}%{_libdir}/keyutil/
%{__install} -d -m 0755 %{buildroot}%{_bindir}/
%{__install} keyutil-%{version}.jar %{buildroot}%{_libdir}/keyutil/
%{__install} -m 0755 keyutil %{buildroot}%{_bindir}/

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/keyutil/keyutil-%{version}.jar
%{_bindir}/keyutil

%doc

%changelog