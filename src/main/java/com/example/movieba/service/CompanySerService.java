package com.example.movieba.service;

import com.example.movieba.model.response.company.ComSerResponse;

import java.util.List;

public interface CompanySerService {
    void buyService(long serviceId,long comId);

    List<ComSerResponse> getAllByIdCom(long idCom);
}
