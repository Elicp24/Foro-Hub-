package com.aluraForoHub.ForoHub.domain;


import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.LocalDateTime;

@Table(name = "topico")
@Entity(name = "Topico")
@EqualsAndHashCode(of = "id")
public class Topico {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "El título no puede estar vacío")
    @Size(min = 5, max = 100, message = "El título debe tener entre 5 y 100 caracteres")
    private String titulo;

    @NotBlank(message = "El mensaje no puede estar vacío")
    @Size(min = 10, max = 500, message = "El mensaje debe tener entre 10 y 500 caracteres")
    private String mensaje;

    @NotNull(message = "La fecha de creación es obligatoria")
    private LocalDateTime fechaCreacion;

    @NotBlank(message = "El status no puede estar vacío")
    private String status;

    @NotBlank(message = "El autor no puede estar vacío")
    private String autor;

    @NotBlank(message = "El curso no puede estar vacío")
    private String curso;


    public Long getId() {
        return id;
    }

    public String getTitulo() {
        return titulo;
    }

    public String getMensaje() {
        return mensaje;
    }

    public LocalDateTime getFechaCreacion() {
        return fechaCreacion;
    }

    public String getStatus() {
        return status;
    }

    public String getAutor() {
        return autor;
    }

    public String getCurso() {
        return curso;
    }

    public void setTitulo(@NotBlank(message = "El título no puede estar vacío") @Size(min = 5, max = 100, message = "El título debe tener entre 5 y 100 caracteres") String titulo) {
        this.titulo = titulo;
    }

    public void setMensaje(@NotBlank(message = "El mensaje no puede estar vacío") @Size(min = 10, max = 500, message = "El mensaje debe tener entre 10 y 500 caracteres") String mensaje) {
    }

    public void setStatus(@NotBlank(message = "El status no puede estar vacío") String status) {
    }

    public void setAutor(@NotBlank(message = "El autor no puede estar vacío") String autor) {
    }

    public void setCurso(@NotBlank(message = "El curso no puede estar vacío") String curso) {
    }

    public void setFechaCreacion(LocalDateTime now) {
    }
}
