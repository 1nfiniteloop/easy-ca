module application.json_subject;

import std.json;


const(string)[string] readJsonFormattedSubject(const string jsonFormattedSubject)
{
    string[string] items;
    auto jsonSubject = parseJSON(jsonFormattedSubject);
    foreach (ref const string key, ref const JSONValue val; jsonSubject.object)
    {
        items[key] = val.str;
    }
    return items;  // to!(string[string])(items.object);  // Doesn't work, must convert the json value to a string first, else the value is surrounded with "<value>".
}

