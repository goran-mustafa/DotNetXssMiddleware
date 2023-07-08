using DotNetXssMiddleware.Middlewares;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using System.Text;

namespace DotNetXssMiddleware.Tests;

public class AntiXssMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_MaliciousQueryString_ReturnsBadRequest()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString("?test=<script>alert('xss')</script>");
        var middleware = new AntiXssMiddleware(next: (innerContext) => Task.FromResult(0));

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.Equal(400, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_MaliciousUrlPath_ReturnsBadRequest()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.Path = "/<script>alert('xss')</script>";
        var middleware = new AntiXssMiddleware(next: (innerContext) => Task.FromResult(0));

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.Equal(400, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_MaliciousForm_ReturnsBadRequest()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Form = new FormCollection(new Dictionary<string, StringValues>
            {
                { "test", "<script>alert('xss')</script>" }
            });
        var middleware = new AntiXssMiddleware(next: (innerContext) => Task.FromResult(0));

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.Equal(400, context.Response.StatusCode);
    }

    [Fact]
    public async Task InvokeAsync_MaliciousJsonBody_ReturnsBadRequest()
    {
        // Arrange
        var context = new DefaultHttpContext();
        context.Request.ContentType = "application/json";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"test\":\"<script>alert('xss')</script>\"}"));
        var middleware = new AntiXssMiddleware(next: (innerContext) => Task.FromResult(0));

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        Assert.Equal(400, context.Response.StatusCode);
    }
}