package com.example.movieba.model.response.company;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Setter
@Getter
public class ComSerResponse {
    private long idComSer;
    private String nameComSer;
    private long numberNews;
    private Date timeStart;
    private Date timeEnd;
}
