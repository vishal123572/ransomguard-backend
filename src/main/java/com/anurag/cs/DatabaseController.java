package com.anurag.cs;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/** Read-only inspection of the application's catalog, restricted by /api/admin/** security. */
@RestController
@RequestMapping("/api/admin/database")
public class DatabaseController {
    private static final int PAGE_SIZE = 25;
    private final JdbcTemplate jdbc;

    public DatabaseController(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    public record TableInfo(String name, long rows) {}
    public record ColumnInfo(String name, String type, boolean nullable, boolean primaryKey, boolean protectedValue) {}
    public record CatalogView(String name, List<TableInfo> tables) {}
    public record TableView(String name, List<ColumnInfo> columns, List<Map<String, Object>> rows, long total, int page, int pageSize) {}

    @GetMapping
    public CatalogView catalog() {
        return jdbc.execute((ConnectionCallback<CatalogView>) connection -> {
            var tables = new ArrayList<TableInfo>();
            for (String name : tableNames(connection)) tables.add(new TableInfo(name, count(connection, name)));
            return new CatalogView(connection.getCatalog(), tables);
        });
    }

    @GetMapping("/table")
    public TableView table(@RequestParam String name, @RequestParam(defaultValue = "0") int page) {
        if (page < 0 || page > 100000) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid page number.");
        return jdbc.execute((ConnectionCallback<TableView>) connection -> {
            if (!tableNames(connection).contains(name)) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Table not found.");
            List<ColumnInfo> columns = columns(connection, name);
            var selected = new ArrayList<String>();
            for (ColumnInfo column : columns) {
                if (passwordHashColumn(name, column.name())) {
                    String field = quote(connection, column.name());
                    // This admin-only exception displays valid BCrypt hashes, never plaintext passwords.
                    selected.add("CASE WHEN " + field + " REGEXP '^[$]2[aby][$][0-9]{2}[$][./A-Za-z0-9]{53}$' THEN "
                        + field + " ELSE '[protected]' END AS " + field);
                    continue;
                }
                // Sensitive columns are replaced in SQL, so their values never leave the database.
                selected.add(column.protectedValue() ? "'[protected]' AS " + quote(connection, column.name()) : quote(connection, column.name()));
            }
            String order = columns.stream().filter(ColumnInfo::primaryKey).map(ColumnInfo::name).findFirst().orElse(columns.getFirst().name());
            String sql = "SELECT " + String.join(", ", selected) + " FROM " + quote(connection, name)
                + " ORDER BY " + quote(connection, order) + " LIMIT " + PAGE_SIZE + " OFFSET " + ((long) page * PAGE_SIZE);
            var rows = new ArrayList<Map<String, Object>>();
            try (var statement = connection.createStatement(); var result = statement.executeQuery(sql)) {
                while (result.next()) {
                    var row = new java.util.LinkedHashMap<String, Object>();
                    for (ColumnInfo column : columns) {
                        Object value = result.getObject(column.name());
                        if (value instanceof byte[]) value = "[binary data]";
                        row.put(column.name(), value);
                    }
                    rows.add(row);
                }
            }
            return new TableView(name, columns, rows, count(connection, name), page, PAGE_SIZE);
        });
    }

    private List<String> tableNames(Connection connection) throws SQLException {
        var names = new ArrayList<String>();
        try (ResultSet tables = connection.getMetaData().getTables(connection.getCatalog(), null, "%", new String[]{"TABLE"})) {
            while (tables.next()) names.add(tables.getString("TABLE_NAME"));
        }
        names.sort(Comparator.naturalOrder());
        return names;
    }

    private List<ColumnInfo> columns(Connection connection, String name) throws SQLException {
        var keys = new ArrayList<String>();
        try (ResultSet result = connection.getMetaData().getPrimaryKeys(connection.getCatalog(), null, name)) {
            while (result.next()) keys.add(result.getString("COLUMN_NAME"));
        }
        var columns = new ArrayList<ColumnInfo>();
        // '_' and '%' in table names are JDBC patterns. Filter to the exact table before accepting a column.
        try (ResultSet result = connection.getMetaData().getColumns(connection.getCatalog(), null, name, "%")) {
            while (result.next()) {
                if (!name.equals(result.getString("TABLE_NAME"))) continue;
                String column = result.getString("COLUMN_NAME");
                columns.add(new ColumnInfo(column, result.getString("TYPE_NAME"), result.getInt("NULLABLE") != 0, keys.contains(column), sensitive(column) && !passwordHashColumn(name, column)));
            }
        }
        return columns;
    }

    static boolean sensitive(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.contains("password") || lower.contains("secret") || lower.contains("token") || lower.contains("credential");
    }

    static boolean passwordHashColumn(String table, String column) {
        return "cs_users".equals(table) && "password_hash".equals(column);
    }

    private long count(Connection connection, String name) throws SQLException {
        try (var statement = connection.createStatement(); var result = statement.executeQuery("SELECT COUNT(*) FROM " + quote(connection, name))) {
            result.next(); return result.getLong(1);
        }
    }

    static String quote(Connection connection, String identifier) throws SQLException {
        String q = connection.getMetaData().getIdentifierQuoteString().strip();
        if (q.isEmpty()) throw new SQLException("Database does not support quoted identifiers.");
        return q + identifier.replace(q, q + q) + q;
    }
}
