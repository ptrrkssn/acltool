# Documentation: https://docs.brew.sh/Formula-Cookbook
#                https://rubydoc.brew.sh/Formula
class Acltool < Formula
  desc "A tool to manipulate NFSv4/ZFS ACLs (and more) on Linux, FreeBSD, Solaris & MacOS"
  homepage ""
  url "https://github.com/ptrrkssn/acltool/archive/v1.15.tar.gz"
  sha256 "adee348dd6bf04395bc0c692a4cc6e849fcea213a601e6e5f7dbfb207f26b4a6"

  depends_on "readline" => :recommended
#  depends_on "libsmbclient" => :recommended
  
  def install
    system "./configure", "--prefix=#{prefix}"
    system "make install"
  end

  test do
    system "#{bin}/acltool", "lac", "."
  end
end
