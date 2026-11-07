# Fallbacks so the same spec also builds on Debian/Ubuntu (rpm there lacks these macros).
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}
%{!?_presetdir: %global _presetdir /usr/lib/systemd/system-preset}
%{!?_sysusersdir: %global _sysusersdir /usr/lib/sysusers.d}

Name:           netlimiter
Version:        1.0.0
Release:        1%{?dist}
Summary:        Network limiter and monitor for Fedora

License:        MIT
URL:            https://example.com/netlimiter
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust
BuildRequires:  cargo
BuildRequires:  python3-devel
BuildRequires:  systemd-rpm-macros

Requires:       nftables
Requires:       iproute
Requires:       iproute-tc
Requires:       python3-gobject
Requires:       gtk4
Requires:       libadwaita

%description
NetLimiter is a network monitoring and rate-limiting tool for Fedora.
It provides per-application bandwidth control via nftables and tc, with a
GTK4/libadwaita front-end and interactive desktop notifications.

%prep
%autosetup

%build
cd backend
cargo build --release --offline || cargo build --release

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libexecdir}/netlimiter
mkdir -p %{buildroot}%{_datadir}/netlimiter
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_datadir}/polkit-1/actions
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_localstatedir}/lib/netlimiter
mkdir -p %{buildroot}%{_sysusersdir}
mkdir -p %{buildroot}%{_presetdir}

install -m 755 backend/target/release/netlimiterd %{buildroot}%{_bindir}/netlimiterd
install -m 755 gui/main.py %{buildroot}%{_bindir}/netlimiter-gui
install -m 755 gui/netlimiter_notifier.py %{buildroot}%{_libexecdir}/netlimiter/netlimiter_notifier.py
install -m 644 gui/netlimiter-gui.desktop %{buildroot}%{_datadir}/applications/netlimiter-gui.desktop
install -m 644 packaging/netlimiter-daemon.service %{buildroot}%{_unitdir}/netlimiter-daemon.service
install -m 644 packaging/com.netlimiter.policy %{buildroot}%{_datadir}/polkit-1/actions/com.netlimiter.policy
install -m 644 packaging/netlimiter.sysusers %{buildroot}%{_sysusersdir}/netlimiter.conf
install -m 644 packaging/90-netlimiter.preset %{buildroot}%{_presetdir}/90-netlimiter.preset

%files
%license LICENSE
%{_bindir}/netlimiterd
%{_bindir}/netlimiter-gui
%{_libexecdir}/netlimiter/netlimiter_notifier.py
%{_datadir}/applications/netlimiter-gui.desktop
%{_unitdir}/netlimiter-daemon.service
%{_datadir}/polkit-1/actions/com.netlimiter.policy
%{_sysusersdir}/netlimiter.conf
%{_presetdir}/90-netlimiter.preset
%dir %{_localstatedir}/lib/netlimiter
%attr(0755, root, netlimiter) %dir %{_localstatedir}/lib/netlimiter

%post
%sysusers_create_compat %{name}.conf
%systemd_post netlimiter-daemon.service

%preun
%systemd_preun netlimiter-daemon.service

%postun
%systemd_postun_with_restart netlimiter-daemon.service

%changelog
* Fri Nov 06 2026 Mohamed <ziramziram1994@gmail.com> - 1.0.0-1
- Strict speed limiting with tc (HTB + IFB); nftables only as fallback
- Per-application packet-level traffic counters

* Mon Nov 04 2024 Your Name <you@example.com> - 0.2.0-1
- Add interactive desktop notifications with block/allow/limit actions
- Keep closed apps visible in the UI
- Fix auto-block re-application after manual unblock
- Add temporary pause button
