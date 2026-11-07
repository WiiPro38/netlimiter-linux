PREFIX ?= /usr
BINDIR = $(DESTDIR)$(PREFIX)/bin
LIBEXECDIR = $(DESTDIR)$(PREFIX)/libexec
DATADIR = $(DESTDIR)$(PREFIX)/share
UNITDIR = $(DESTDIR)$(PREFIX)/lib/systemd/system
POLKITDIR = $(DESTDIR)$(PREFIX)/share/polkit-1/actions
APPDIR = $(DATADIR)/applications
SYSCONFDIR = $(DESTDIR)/etc
SYSUSERSDIR = $(DESTDIR)$(PREFIX)/lib/sysusers.d
PRESETDIR = $(DESTDIR)$(PREFIX)/lib/systemd/system-preset
LOCALSTATEDIR = $(DESTDIR)/var/lib/netlimiter

CARGO ?= cargo
# على Ubuntu/Debian: make rpm RPMBUILD_FLAGS=--nodeps (أسماء BuildRequires مختلفة)
RPMBUILD_FLAGS ?=

# ---- معلومات الحزمة العامة ----
NAME     := netlimiter
VERSION  := 1.0.0
PROJDIR  := $(notdir $(CURDIR))
TOPdir   := $(HOME)/rpmbuild
SOURCES  := $(TOPdir)/SOURCES
SPECS    := $(TOPdir)/SPECS
TARBALL  := $(SOURCES)/$(NAME)-$(VERSION).tar.gz
SPECFILE := $(SPECS)/$(NAME).spec

# ---- متغيرات حزمة DEB ----
DEBDIR = packaging/debian
BUILD_DEB_ROOT = $(CURDIR)/debian_build

.PHONY: all backend frontend install clean \
        srpm rpm clean-rpm prepare-rpm deb clean-deb packages clean-packages

# ---- البناء العادي ----
all: backend frontend

backend:
	cd backend && $(CARGO) build --release

frontend:
	python3 -m py_compile gui/main.py
	python3 -m py_compile gui/netlimiter_notifier.py

install: all
	install -d $(BINDIR)
	install -d $(LIBEXECDIR)/netlimiter
	install -d $(DATADIR)/netlimiter
	install -d $(UNITDIR)
	install -d $(POLKITDIR)
	install -d $(APPDIR)
	install -d $(LOCALSTATEDIR)
	install -d $(SYSUSERSDIR)
	install -d $(PRESETDIR)

	install -m 755 backend/target/release/netlimiterd $(BINDIR)/netlimiterd
	install -m 755 gui/main.py $(BINDIR)/netlimiter-gui
	install -m 755 gui/netlimiter_notifier.py $(LIBEXECDIR)/netlimiter/netlimiter_notifier.py
	install -m 644 gui/netlimiter-gui.desktop $(APPDIR)/netlimiter-gui.desktop
	install -m 644 packaging/netlimiter-daemon.service $(UNITDIR)/netlimiter-daemon.service
	install -m 644 packaging/com.netlimiter.policy $(POLKITDIR)/com.netlimiter.policy
	install -m 644 packaging/netlimiter.sysusers $(SYSUSERSDIR)/netlimiter.conf
	install -m 644 packaging/90-netlimiter.preset $(PRESETDIR)/90-netlimiter.preset

clean:
	cd backend && $(CARGO) clean
	rm -rf gui/__pycache__

# ---- أهداف RPM (Fedora / RHEL) ----

prepare-rpm:
	@echo ">> تجهيز شجرة rpmbuild..."
	@mkdir -p $(TOPdir)/BUILD $(TOPdir)/BUILDROOT $(TOPdir)/RPMS $(TOPdir)/SOURCES $(TOPdir)/SPECS $(TOPdir)/SRPMS
	@echo ">> إنشاء الأرشيف $(TARBALL)..."
	@cd .. && tar -czf $(TARBALL) \
	    --exclude='target' \
	    --exclude='__pycache__' \
	    --exclude='*.pyc' \
	    --exclude='.git' \
	    --exclude='*.rpm' \
	    --transform 's,^$(PROJDIR),$(NAME)-$(VERSION),' \
	    $(PROJDIR)
	@echo ">> نسخ $(NAME).spec..."
	@cp packaging/$(NAME).spec $(SPECFILE)
	@echo ">> جاهز: $(TARBALL)"

rpm: prepare-rpm
	@echo ">> بناء RPM..."
	rpmbuild -ba $(RPMBUILD_FLAGS) $(SPECFILE)
	@echo ""
	@echo ">> النتيجة:"
	@ls -1 $(TOPdir)/RPMS/*/$(NAME)-$(VERSION)-*.rpm 2>/dev/null || true
	@ls -1 $(TOPdir)/SRPMS/$(NAME)-$(VERSION)-*.src.rpm 2>/dev/null || true

srpm: prepare-rpm
	@echo ">> بناء SRPM..."
	rpmbuild -bs $(RPMBUILD_FLAGS) $(SPECFILE)
	@ls -1 $(TOPdir)/SRPMS/$(NAME)-$(VERSION)-*.src.rpm 2>/dev/null || true

clean-rpm:
	rm -rf $(TOPdir)/BUILD/$(NAME)-* \
	       $(TOPdir)/BUILDROOT/$(NAME)-* \
	       $(TOPdir)/RPMS/*/$(NAME)-* \
	       $(TOPdir)/SRPMS/$(NAME)-* \
	       $(TARBALL) \
	       $(SPECFILE)

# ---- أهداف DEB (Ubuntu / Debian) ----

deb: all
	@echo ">> تجهيز هيكل حزمة DEB..."
	@rm -rf $(BUILD_DEB_ROOT)
	@mkdir -p $(BUILD_DEB_ROOT)/usr/bin
	@mkdir -p $(BUILD_DEB_ROOT)/usr/libexec/netlimiter
	@mkdir -p $(BUILD_DEB_ROOT)/usr/share/applications
	@mkdir -p $(BUILD_DEB_ROOT)/usr/lib/systemd/system
	@mkdir -p $(BUILD_DEB_ROOT)/usr/share/polkit-1/actions
	@mkdir -p $(BUILD_DEB_ROOT)/var/lib/netlimiter
	@mkdir -p $(BUILD_DEB_ROOT)/usr/lib/sysusers.d
	@mkdir -p $(BUILD_DEB_ROOT)/usr/lib/systemd/system-preset
	@mkdir -p $(BUILD_DEB_ROOT)/DEBIAN

	# نسخ الملفات المطلوبة لهيكل دبيان
	@install -m 755 backend/target/release/netlimiterd $(BUILD_DEB_ROOT)/usr/bin/netlimiterd
	@install -m 755 gui/main.py $(BUILD_DEB_ROOT)/usr/bin/netlimiter-gui
	@install -m 755 gui/netlimiter_notifier.py $(BUILD_DEB_ROOT)/usr/libexec/netlimiter/netlimiter_notifier.py
	@install -m 644 gui/netlimiter-gui.desktop $(BUILD_DEB_ROOT)/usr/share/applications/netlimiter-gui.desktop
	@install -m 644 packaging/netlimiter-daemon.service $(BUILD_DEB_ROOT)/usr/lib/systemd/system/netlimiter-daemon.service
	@install -m 644 packaging/com.netlimiter.policy $(BUILD_DEB_ROOT)/usr/share/polkit-1/actions/com.netlimiter.policy
	@install -m 644 packaging/netlimiter.sysusers $(BUILD_DEB_ROOT)/usr/lib/sysusers.d/netlimiter.conf
	@install -m 644 packaging/90-netlimiter.preset $(BUILD_DEB_ROOT)/usr/lib/systemd/system-preset/90-netlimiter.preset

	# ملف التحكم + سكربتات التثبيت (إنشاء المجموعة وتفعيل الخدمة)
	@cp $(DEBDIR)/control $(BUILD_DEB_ROOT)/DEBIAN/control
	@install -m 755 $(DEBDIR)/postinst $(BUILD_DEB_ROOT)/DEBIAN/postinst
	@install -m 755 $(DEBDIR)/prerm $(BUILD_DEB_ROOT)/DEBIAN/prerm
	@install -m 755 $(DEBDIR)/postrm $(BUILD_DEB_ROOT)/DEBIAN/postrm

	# بناء الحزمة النهائية
	@echo ">> بناء ملف .deb..."
	@dpkg-deb --root-owner-group --build $(BUILD_DEB_ROOT) $(NAME)-$(VERSION)-1_amd64.deb
	@rm -rf $(BUILD_DEB_ROOT)
	@echo ">> تم بنجاح: $(NAME)-$(VERSION)-1_amd64.deb"

clean-deb:
	@rm -f $(NAME)-*.deb

# ---- كل الحزم دفعة واحدة (rpm + deb) ----
# يحتاج: rpmbuild (Fedora: rpm-build / Ubuntu: rpm) و dpkg-deb (Fedora: dpkg / Ubuntu: مثبّت)
packages: rpm deb
	@echo ">> تم بناء حزمتي RPM و DEB"

clean-packages: clean-rpm clean-deb
