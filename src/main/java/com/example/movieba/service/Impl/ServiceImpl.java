package com.example.movieba.service.Impl;


import com.example.movieba.entities.Services;
import com.example.movieba.exception.BusinessCode;
import com.example.movieba.exception.BusinessException;
import com.example.movieba.mapper.ServicesMapper;
import com.example.movieba.model.request.services.ServicesRequest;
import com.example.movieba.repository.ServiceRepository;
import com.example.movieba.service.ServicesRe;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Service
@AllArgsConstructor
public class ServiceImpl implements ServicesRe {

    private final ServicesMapper servicesMapper;

    private final ServiceRepository serviceRepository;


    @Override
    public void createServices(ServicesRequest servicesRequest) {
        Services services = servicesMapper.to(servicesRequest);
        serviceRepository.save(services);
    }

    @Override
    public void updateServices(long idService, ServicesRequest servicesRequest) {
        Optional<Services> findServices = serviceRepository.findById(idService);
        findServices.orElseThrow(()-> new BusinessException(BusinessCode.GAME_NOT_FOUND));

        if (!findServices.isEmpty()){
            Services services = findServices.get();
            services.setNameServices(servicesRequest.getNameServices());
            services.setDescribeService(servicesRequest.getDescribeService());
            services.setPriceService(servicesRequest.getPriceService());
            serviceRepository.save(services);
        }
    }

    @Override
    public void deleteServices(long idService) {
        Optional<Services> findServices = serviceRepository.findById(idService);
        findServices.orElseThrow(()-> new BusinessException(BusinessCode.GAME_NOT_FOUND));

        if (!findServices.isEmpty()){
            serviceRepository.deleteById(idService);
        }

    }

    @Override
    public List<Services> getAllServices() {
        return serviceRepository.findAll();
    }
}
