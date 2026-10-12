package com.anurag.cs;

import java.sql.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class DatabaseControllerTest {
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final Connection connection = mock(Connection.class);
    private final DatabaseMetaData metadata = mock(DatabaseMetaData.class);
    private final DatabaseController controller = new DatabaseController(jdbc);

    @SuppressWarnings("unchecked")
    private void database() throws Exception {
        when(connection.getCatalog()).thenReturn("app");
        when(connection.getMetaData()).thenReturn(metadata);
        when(metadata.getIdentifierQuoteString()).thenReturn("`");
        when(jdbc.execute(any(ConnectionCallback.class))).thenAnswer(call -> ((ConnectionCallback<?>) call.getArgument(0)).doInConnection(connection));
        var tables = mock(ResultSet.class);
        when(metadata.getTables(eq("app"), isNull(), eq("%"), any(String[].class))).thenReturn(tables);
        when(tables.next()).thenReturn(true, false);
        when(tables.getString("TABLE_NAME")).thenReturn("cs_users");
    }

    @Test void refusesTableNamesOutsideTheDatabaseCatalog() throws Exception {
        database();
        var error = assertThrows(ResponseStatusException.class, () -> controller.table("cs_users; DROP TABLE cs_users", 0));
        assertEquals(404, error.getStatusCode().value());
        verify(connection, never()).createStatement();
    }

    @Test void rejectsInvalidPaginationBeforeQuerying() {
        assertEquals(400, assertThrows(ResponseStatusException.class, () -> controller.table("cs_users", -1)).getStatusCode().value());
        assertEquals(400, assertThrows(ResponseStatusException.class, () -> controller.table("cs_users", Integer.MAX_VALUE)).getStatusCode().value());
        verifyNoInteractions(jdbc);
    }

    @Test void masksSensitiveColumnsInSqlAndUsesBoundedPages() throws Exception {
        database();
        var keys = mock(ResultSet.class); when(keys.next()).thenReturn(true, false);
        when(keys.getString("COLUMN_NAME")).thenReturn("id");
        when(metadata.getPrimaryKeys("app", null, "cs_users")).thenReturn(keys);
        var columns = mock(ResultSet.class); when(columns.next()).thenReturn(true, true, true, false);
        when(columns.getString("TABLE_NAME")).thenReturn("cs_users");
        when(columns.getString("COLUMN_NAME")).thenReturn("id", "password", "role");
        when(columns.getString("TYPE_NAME")).thenReturn("BIGINT", "VARCHAR", "VARCHAR");
        when(metadata.getColumns("app", null, "cs_users", "%")).thenReturn(columns);
        var statement = mock(Statement.class); when(connection.createStatement()).thenReturn(statement);
        String sql = "SELECT `id`, '[protected]' AS `password`, `role` FROM `cs_users` ORDER BY `id` LIMIT 25 OFFSET 25";
        var records = mock(ResultSet.class); when(records.next()).thenReturn(true, false);
        when(records.getObject("id")).thenReturn(26L); when(records.getObject("password")).thenReturn("[protected]");
        when(records.getObject("role")).thenReturn("ADMIN"); when(statement.executeQuery(sql)).thenReturn(records);
        var count = mock(ResultSet.class); when(count.getLong(1)).thenReturn(30L);
        when(statement.executeQuery("SELECT COUNT(*) FROM `cs_users`")).thenReturn(count);
        var result = controller.table("cs_users", 1);
        assertEquals(30, result.total()); assertEquals(25, result.pageSize());
        assertEquals("[protected]", result.rows().getFirst().get("password"));
        assertTrue(result.columns().get(1).protectedValue());
        assertTrue(result.columns().getFirst().primaryKey());
        verify(statement).executeQuery(sql);
    }

    @Test void sensitiveColumnNamesAreCaseInsensitive() {
        for (String name : List.of("password_hash", "JWT_TOKEN", "clientSecret", "credential")) assertTrue(DatabaseController.sensitive(name));
        assertFalse(DatabaseController.sensitive("role"));
    }

    @Test void hashDisplayIsRestrictedToTheUsersPasswordHashColumn() {
        assertTrue(DatabaseController.passwordHashColumn("cs_users", "password_hash"));
        assertFalse(DatabaseController.passwordHashColumn("other_users", "password_hash"));
        assertFalse(DatabaseController.passwordHashColumn("cs_users", "password"));
        assertFalse(DatabaseController.passwordHashColumn("cs_users", "jwt_token"));
    }

    @Test void displaysBcryptHashesWhileMaskingTokensAndInvalidPasswordValuesInSql() throws Exception {
        database();
        var keys = mock(ResultSet.class); when(keys.next()).thenReturn(true, false);
        when(keys.getString("COLUMN_NAME")).thenReturn("id");
        when(metadata.getPrimaryKeys("app", null, "cs_users")).thenReturn(keys);
        var columns = mock(ResultSet.class); when(columns.next()).thenReturn(true, true, true, false);
        when(columns.getString("TABLE_NAME")).thenReturn("cs_users");
        when(columns.getString("COLUMN_NAME")).thenReturn("id", "password_hash", "jwt_token");
        when(columns.getString("TYPE_NAME")).thenReturn("BIGINT", "VARCHAR", "VARCHAR");
        when(metadata.getColumns("app", null, "cs_users", "%")).thenReturn(columns);
        var statement = mock(Statement.class); when(connection.createStatement()).thenReturn(statement);
        String sql = "SELECT `id`, CASE WHEN `password_hash` REGEXP '^[$]2[aby][$][0-9]{2}[$][./A-Za-z0-9]{53}$' THEN `password_hash` ELSE '[protected]' END AS `password_hash`, '[protected]' AS `jwt_token` FROM `cs_users` ORDER BY `id` LIMIT 25 OFFSET 0";
        String hash = "$2a$10$" + "A".repeat(53);
        var records = mock(ResultSet.class); when(records.next()).thenReturn(true, false);
        when(records.getObject("id")).thenReturn(1L);
        when(records.getObject("password_hash")).thenReturn(hash);
        when(records.getObject("jwt_token")).thenReturn("[protected]");
        when(statement.executeQuery(sql)).thenReturn(records);
        var count = mock(ResultSet.class); when(count.getLong(1)).thenReturn(1L);
        when(statement.executeQuery("SELECT COUNT(*) FROM `cs_users`")).thenReturn(count);
        var result = controller.table("cs_users", 0);
        assertEquals(hash, result.rows().getFirst().get("password_hash"));
        assertEquals("[protected]", result.rows().getFirst().get("jwt_token"));
        assertFalse(result.columns().get(1).protectedValue());
        assertTrue(result.columns().get(2).protectedValue());
        verify(statement).executeQuery(sql);
    }
}
