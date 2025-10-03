using Microsoft.AspNetCore.Mvc;

namespace new_assistant.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new { 
            Status = "Healthy", 
            Timestamp = DateTime.UtcNow,
            Application = "KeyCloak Assistant API"
        });
    }
}
