using Microsoft.EntityFrameworkCore;
using new_assistant.Core.Entities;
using System.Text.Json;

namespace new_assistant.Infrastructure.Data;

/// <summary>
/// Контекст базы данных приложения.
/// </summary>
public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }
    
    public DbSet<KeycloakClient> KeycloakClients { get; set; }
    public DbSet<ClientUserAccess> ClientUserAccess { get; set; }
    public DbSet<AuditLog> AuditLogs { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // Конфигурация KeycloakClient
        modelBuilder.Entity<KeycloakClient>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.KeycloakClientId).IsUnique();
            entity.HasIndex(e => e.CreatedByUserId);
            entity.HasIndex(e => e.CreatedAt);
            
            // JSON сериализация для списка RedirectUris
            entity.Property(e => e.RedirectUris)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>()
                );
            
            // Связь один-ко-многим с ClientUserAccess
            entity.HasMany(e => e.UserAccess)
                .WithOne(e => e.KeycloakClient)
                .HasForeignKey(e => e.KeycloakClientId)
                .OnDelete(DeleteBehavior.Cascade);
        });
        
        // Конфигурация ClientUserAccess
        modelBuilder.Entity<ClientUserAccess>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.KeycloakClientId, e.UserId }).IsUnique();
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.GrantedAt);
        });
        
        // Конфигурация AuditLog
        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.EventType);
            entity.HasIndex(e => e.Category);
            entity.HasIndex(e => e.KeycloakClientId);
            
            // Связь с KeycloakClient (опциональная)
            entity.HasOne(e => e.KeycloakClient)
                .WithMany()
                .HasForeignKey(e => e.KeycloakClientId)
                .OnDelete(DeleteBehavior.SetNull);
        });
    }
}
