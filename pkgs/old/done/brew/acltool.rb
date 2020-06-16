# Documentation: https://docs.brew.sh/Formula-Cookbook
#                https://rubydoc.brew.sh/Formula
class Acltool < Formula
  desc "A tool to manipulate NFSv4/ZFS ACLs (and more) on MacOS, Linux, FreeBSD & Solaris"
  homepage "https://github.com/ptrrkssn/acltool"
  url "https://github.com/ptrrkssn/acltool/archive/v1.16.3.tar.gz"

  ## This line must be uncommented and updated with the correct hash value
  ## The correct value will be displayed when doing 'brew install acltool'
  # sha256 "15430b64cb493571f6e46a38482402746bee7ed134c0e99d7976d231cab1c7d5"

  depends_on "readline" => :recommended

  ## Needs Samba's libsmbclient for native SMB support, but we don't force
  ## it to be installed currently since it brings to much other cruft.
  #  depends_on "libsmbclient" => :recommended
  
  def install
    system "./configure", "--prefix=#{prefix}"
    system "make install"
  end

  test do
    system "#{bin}/acltool", "lac", "-v", "."
  end
end
