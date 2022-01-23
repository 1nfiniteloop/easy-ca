module application.stubs.certificate_db;

import application.io : CertificateDatabaseStorage;

class CertificateDatabaseStorageMock : CertificateDatabaseStorage
{
  private struct Probe
  {
    uint readCalls = 0;
    uint writeCalls = 0;
  }

  private Probe probe;
  private string jsonFormattedData;

  this(const string jsonFormattedData = "")
  {
    this.jsonFormattedData = jsonFormattedData;
  }

  const(string) read()
  {
    probe.readCalls++;
    return jsonFormattedData;
  }

  uint readCalls()
  {
    return probe.readCalls;
  }

  void write(const string data)
  {
    probe.writeCalls++;
    jsonFormattedData = data;
  }

  uint writeCalls()
  {
    return probe.writeCalls;
  }
}
