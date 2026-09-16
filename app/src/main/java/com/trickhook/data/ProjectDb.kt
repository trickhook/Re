package com.trickhook.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Project database — the Nocturne equivalent of IDA/Ghidra's project DB.
 *
 * Tables:
 *  projects   – one row per opened binary (keyed by canonical path)
 *  renames    – user function/label renames per project
 *  comments   – per-address comments
 *  bookmarks  – named address bookmarks
 *  notes      – free-form notes
 */
class ProjectDb(context: Context) : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {

    companion object {
        const val DB_NAME = "nocturne_analysis.db"
        const val DB_VERSION = 2
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("""
            CREATE TABLE projects(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                format TEXT,
                arch TEXT,
                created_at INTEGER,
                last_opened INTEGER
            )""")
        db.execSQL("""
            CREATE TABLE renames(
                project_id INTEGER NOT NULL,
                addr TEXT NOT NULL,
                old_name TEXT,
                new_name TEXT NOT NULL,
                created_at INTEGER,
                PRIMARY KEY(project_id, addr),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            )""")
        db.execSQL("""
            CREATE TABLE comments(
                project_id INTEGER NOT NULL,
                addr TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at INTEGER,
                PRIMARY KEY(project_id, addr),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            )""")
        db.execSQL("""
            CREATE TABLE bookmarks(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                addr TEXT NOT NULL,
                label TEXT NOT NULL,
                created_at INTEGER,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            )""")
        db.execSQL("""
            CREATE TABLE notes(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT,
                created_at INTEGER,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            )""")
        db.execSQL("CREATE INDEX idx_renames_pid ON renames(project_id)")
        db.execSQL("CREATE INDEX idx_comments_pid ON comments(project_id)")
        db.execSQL("CREATE INDEX idx_bookmarks_pid ON bookmarks(project_id)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldV: Int, newV: Int) {
        db.execSQL("DROP TABLE IF EXISTS notes")
        db.execSQL("DROP TABLE IF EXISTS bookmarks")
        db.execSQL("DROP TABLE IF EXISTS comments")
        db.execSQL("DROP TABLE IF EXISTS renames")
        db.execSQL("DROP TABLE IF EXISTS projects")
        onCreate(db)
    }

    // ------------------------------------------------------------ projects --
    fun upsertProject(path: String, name: String, format: String?, arch: String?): Long {
        val now = System.currentTimeMillis()
        val db = writableDatabase
        val cur = db.rawQuery("SELECT id FROM projects WHERE path=?", arrayOf(path))
        val id: Long = if (cur.moveToFirst()) {
            val existing = cur.getLong(0)
            cur.close()
            db.update("projects", ContentValues().apply {
                put("name", name); put("format", format); put("arch", arch)
                put("last_opened", now)
            }, "id=?", arrayOf(existing.toString()))
            existing
        } else {
            cur.close()
            db.insert("projects", null, ContentValues().apply {
                put("path", path); put("name", name)
                put("format", format); put("arch", arch)
                put("created_at", now); put("last_opened", now)
            })
        }
        return id
    }

    fun projectId(path: String): Long =
        readableDatabase.rawQuery("SELECT id FROM projects WHERE path=?", arrayOf(path)).use { c ->
            if (c.moveToFirst()) c.getLong(0) else -1L
        }

    fun recentProjects(limit: Int = 12): List<RecentProject> =
        readableDatabase.rawQuery(
            "SELECT id, path, name, format, arch, last_opened FROM projects ORDER BY last_opened DESC LIMIT ?",
            arrayOf(limit.toString())).use { c ->
            val out = mutableListOf<RecentProject>()
            while (c.moveToNext()) out.add(
                RecentProject(c.getLong(0), c.getString(1), c.getString(2),
                    c.getString(3) ?: "", c.getString(4) ?: "", c.getLong(5))
            )
            out
        }

    fun deleteProject(id: Long) {
        val db = writableDatabase
        db.delete("renames", "project_id=?", arrayOf(id.toString()))
        db.delete("comments", "project_id=?", arrayOf(id.toString()))
        db.delete("bookmarks", "project_id=?", arrayOf(id.toString()))
        db.delete("notes", "project_id=?", arrayOf(id.toString()))
        db.delete("projects", "id=?", arrayOf(id.toString()))
    }

    // ------------------------------------------------------------- renames --
    fun rename(pid: Long, addr: String, oldName: String?, newName: String) {
        writableDatabase.insertWithOnConflict("renames", null, ContentValues().apply {
            put("project_id", pid); put("addr", addr)
            put("old_name", oldName); put("new_name", newName)
            put("created_at", System.currentTimeMillis())
        }, SQLiteDatabase.CONFLICT_REPLACE)
    }

    /** Drop one rename, so a plugin run can be rolled back to "no rename". */
    fun deleteRename(pid: Long, addr: String) {
        writableDatabase.delete("renames", "project_id=? AND addr=?",
            arrayOf(pid.toString(), addr))
    }

    fun renames(pid: Long): Map<String, String> =
        readableDatabase.query("renames", arrayOf("addr", "new_name"),
            "project_id=?", arrayOf(pid.toString()), null, null, null).use { c ->
            val m = mutableMapOf<String, String>()
            while (c.moveToNext()) m[c.getString(0)] = c.getString(1)
            m
        }

    // ------------------------------------------------------------ comments --
    fun comment(pid: Long, addr: String, text: String) {
        writableDatabase.insertWithOnConflict("comments", null, ContentValues().apply {
            put("project_id", pid); put("addr", addr); put("comment", text)
            put("created_at", System.currentTimeMillis())
        }, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun comments(pid: Long): Map<String, String> =
        readableDatabase.query("comments", arrayOf("addr", "comment"),
            "project_id=?", arrayOf(pid.toString()), null, null, null).use { c ->
            val m = mutableMapOf<String, String>()
            while (c.moveToNext()) m[c.getString(0)] = c.getString(1)
            m
        }

    fun deleteComment(pid: Long, addr: String) {
        writableDatabase.delete("comments", "project_id=? AND addr=?",
            arrayOf(pid.toString(), addr))
    }

    // ----------------------------------------------------------- bookmarks --
    fun bookmark(pid: Long, addr: String, label: String): Long =
        writableDatabase.insert("bookmarks", null, ContentValues().apply {
            put("project_id", pid); put("addr", addr); put("label", label)
            put("created_at", System.currentTimeMillis())
        })

    fun bookmarks(pid: Long): List<Bookmark> =
        readableDatabase.query("bookmarks", arrayOf("id", "addr", "label"),
            "project_id=?", arrayOf(pid.toString()), null, null, "created_at DESC").use { c ->
            val out = mutableListOf<Bookmark>()
            while (c.moveToNext()) out.add(Bookmark(c.getLong(0), c.getString(1), c.getString(2)))
            out
        }

    fun deleteBookmark(id: Long) {
        writableDatabase.delete("bookmarks", "id=?", arrayOf(id.toString()))
    }

    // --------------------------------------------------------------- notes --
    fun note(pid: Long, title: String, body: String): Long =
        writableDatabase.insert("notes", null, ContentValues().apply {
            put("project_id", pid); put("title", title); put("body", body)
            put("created_at", System.currentTimeMillis())
        })

    fun notes(pid: Long): List<Note> =
        readableDatabase.query("notes", arrayOf("id", "title", "body", "created_at"),
            "project_id=?", arrayOf(pid.toString()), null, null, "created_at DESC").use { c ->
            val out = mutableListOf<Note>()
            while (c.moveToNext()) out.add(Note(c.getLong(0), c.getString(1), c.getString(2) ?: "", c.getLong(3)))
            out
        }

    fun deleteNote(id: Long) {
        writableDatabase.delete("notes", "id=?", arrayOf(id.toString()))
    }
}

data class RecentProject(
    val id: Long, val path: String, val name: String,
    val format: String, val arch: String, val lastOpened: Long
)

data class Bookmark(val id: Long, val addr: String, val label: String)
data class Note(val id: Long, val title: String, val body: String, val createdAt: Long)
