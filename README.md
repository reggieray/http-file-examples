# HTTP File Examples

This is an example project showcasing HTTP file examples together with this accompanying [blog post](https://matthewregis.dev/posts/http-files).

The `.http` file [http-file-examples.http](http-file-examples.http) consists of GET, POST, PUT & DELETE requests based on the exposed endpoints from the mock todo minimal API. 

A `.env` file has also been included to demonstrate its usage.

> **_NOTE:_**  `.env` should not be committed to source control if containing sensitive information 

# Get Started

Start the API

```
dotnet run 
```

Use the `.http` file either in Visual Studio 

<img src="http-file-example-vs.gif" style="max-width: 100%">

or vscode using the [REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client) extension.

<img src="http-file-example-vs-code.gif" style="max-width: 100%">

