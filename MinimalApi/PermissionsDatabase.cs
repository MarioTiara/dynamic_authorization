using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace Dynamic_Authorization
{
    public class PermissionsDatabase
    {
        private readonly string dbPath;
        public PermissionsDatabase (IWebHostEnvironment env) => this.dbPath=Path.Combine(env.ContentRootPath, "permissions.json");
        private Dictionary<string, HashSet<string>>? Record => File.Exists(this.dbPath)
            ? JsonSerializer.Deserialize<Dictionary<string, HashSet<string>>>(File.ReadAllText(this.dbPath))
            :new (); 
        
        public bool HasPermission(string userId, string permission){
            var db=Record;
            if (db==null) return false;
            return db.ContainsKey(userId) && db[userId].Contains(permission);
        }

        public void AddPermission(string userId, string permission){
            var db=Record;
            if (db==null) return;
            if (!db.ContainsKey(userId)) db[userId]= new HashSet<string>();
            db[userId].Add(permission);
            File.WriteAllText(dbPath, JsonSerializer.Serialize(db));
        }

        public void RemovePermission(string userId, string permission){
            var db=Record;
            if (db==null) return;
            if (db[userId]==null || !db[userId].Contains(permission)) return;
            db[userId].Remove(permission);
            File.WriteAllText(dbPath, JsonSerializer.Serialize(db, new JsonSerializerOptions(){
                WriteIndented=true
            }));

        }

    }
}