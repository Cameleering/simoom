using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.ClearProviders();
var port = int.Parse(Environment.GetEnvironmentVariable("PORT") ?? "8080");
builder.WebHost.ConfigureKestrel(k =>
{
    k.Limits.MaxConcurrentConnections = null;
    k.ListenAnyIP(port, o => o.Protocols = HttpProtocols.Http1);
    k.ListenAnyIP(port + 1, o => o.Protocols = HttpProtocols.Http2); // h2c needs its own port
});
var app = builder.Build();
app.MapGet("/", () => Results.Text("Hello, World!", "text/plain"));
app.MapPost("/echo", async (HttpRequest r) =>
{
    using var ms = new MemoryStream();
    await r.Body.CopyToAsync(ms);
    return Results.Bytes(ms.ToArray(), "application/json");
});
app.Run();
