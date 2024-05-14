using WebAPI;

var builder = WebApplication.CreateBuilder(args);

// create new instance of Startup
var startup = new Startup(builder.Configuration);

// configure all services
startup.ConfigureServices(builder.Services);
    
var app = builder.Build();

startup.Configure(app);

app.Run();
