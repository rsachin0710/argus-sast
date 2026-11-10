package com.example.demo;

// DELIBERATELY VULNERABLE example used to demo and test Argus. Do not deploy.

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    private static final String DB_PASSWORD = "Sup3rS3cretPw!";
    private Connection connection;

    // SQL injection: username is concatenated into the query.
    @GetMapping("/search")
    public ResultSet search(@RequestParam String username) throws Exception {
        Statement stmt = connection.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }

    // Safe: parameterised query (should NOT be reported).
    @GetMapping("/byId")
    public ResultSet byId(@RequestParam int id) throws Exception {
        PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setInt(1, id);
        return ps.executeQuery();
    }

    // Path traversal: file name comes from the request.
    @GetMapping("/avatar")
    public byte[] avatar(@RequestParam String file) throws Exception {
        File f = new File("/var/app/avatars/" + file);
        try (FileInputStream in = new FileInputStream(f)) {
            return in.readAllBytes();
        }
    }

    // OS command injection.
    @PostMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(p.getInputStream().readAllBytes());
    }

    // Insecure deserialization of the request body.
    @PostMapping("/import")
    public Object importUser(javax.servlet.http.HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        return ois.readObject();
    }

    // XXE: parser created without disabling DTDs.
    @PostMapping("/xml")
    public String parseXml(javax.servlet.http.HttpServletRequest request) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(request.getInputStream()).getDocumentElement().getTextContent();
    }

    // Weak password hashing.
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new java.math.BigInteger(1, md.digest(password.getBytes())).toString(16);
    }

    // Open redirect.
    @GetMapping("/go")
    public void go(@RequestParam String next, HttpServletResponse response) throws Exception {
        response.sendRedirect(next);
    }
}
