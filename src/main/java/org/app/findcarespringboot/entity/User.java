package org.app.findcarespringboot.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
public class User {
    @Id
    private String username;
    private String password;

    @OneToMany(mappedBy = "user")
    private List<FoundPost> foundPosts;

    public User(String username, String password) {
        this.username = username.toLowerCase();
        this.password = password;
    }
}
