import std.stdio;

import std.file : FileException;
import std.json : JSONException;

import infiniteloop.openssl : OpenSSLError;

import application.error;
import application.cmdline.app;

void main(string[] args)
{
  auto app = new CmdlineApplication(args);
  try
  {
    app.run();
  }
  catch (FileException err)
  {
    writeln("FileError: ", err.msg);
  }
  catch (JSONException err)
  {
    writeln("JsonError: ", err.msg);
  }
  catch (OpenSSLError err)
  {
    writeln("OpenSSLError: ", err.msg);
  }
  catch (CmdlineArgumentError err)
  {
    writeln("Cmdline argument error: ", err.msg);
    app.help();
  }
  catch (ApplicationError err)
  {
    writeln("Application error: ", err.msg);
  }
}
