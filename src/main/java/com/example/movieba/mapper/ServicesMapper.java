package com.example.movieba.mapper;

import com.example.movieba.entities.Services;
import com.example.movieba.model.request.services.ServicesRequest;
import com.example.movieba.utils.BeanUtils;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class ServicesMapper implements Mapper{

    public Services to(ServicesRequest servicesRequest){

        Services services = new Services();
        BeanUtils.refine(servicesRequest,services,BeanUtils::copyNonNull);
        return services;
    }
}
