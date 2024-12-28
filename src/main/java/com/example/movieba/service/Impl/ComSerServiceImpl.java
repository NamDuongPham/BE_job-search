package com.example.movieba.service.Impl;

import com.example.movieba.entities.Company;
import com.example.movieba.entities.CompanyServices;
import com.example.movieba.entities.Services;
import com.example.movieba.model.response.company.ComSerResponse;
import com.example.movieba.repository.CompanyRepository;
import com.example.movieba.repository.CompanyServicesRepository;
import com.example.movieba.repository.ServiceRepository;
import com.example.movieba.repository.UserRepository;
import com.example.movieba.service.CompanySerService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class ComSerServiceImpl implements CompanySerService {
    private final CompanyServicesRepository companyServicesRepository;
    private final CompanyRepository companyRepository;
    private final UserRepository userRepository;

    private final ServiceRepository serviceRepository;

    @Override
    public void buyService(long serviceId, long comId) {
        Optional<Company> findCompanies = companyRepository.findById(comId);
        Optional<Services> findServices = serviceRepository.findById(serviceId);

        if (findCompanies.get() != null && findServices.get()!= null){
            CompanyServices companyServices = new CompanyServices();
            companyServices.setServiceCom(findServices.get());
            companyServices.setCompanySer(findCompanies.get());
            Date date = new Date();
            companyServices.setTimeStart(date);
            companyServices.setTimeEnd(plusTime(date,serviceId));
            companyServicesRepository.save(companyServices);
        }
    }

    @Override
    public List<ComSerResponse> getAllByIdCom(long idCom) {
        Optional<Company> company = companyRepository.findById(idCom);
        if (company.get()!= null){
            List<CompanyServices> comSerResponses = companyServicesRepository.findByCompanySer(company.get());
            return comSerResponses.stream().map(t->{
                ComSerResponse comSer = new ComSerResponse();
                comSer.setIdComSer(t.getIdComService());
                comSer.setNameComSer(t.getServiceCom().getNameServices());
                comSer.setNumberNews(t.getServiceCom().getNumberNews());
                comSer.setTimeStart(t.getTimeStart());
                comSer.setTimeEnd(t.getTimeEnd());
                return comSer;
            }).collect(Collectors.toList());
        }

        return null;
    }


    private Date plusTime(Date timeNow, long idService){
        Optional<Services> findServices = serviceRepository.findById(idService);
        if (findServices.get() != null){
            if (findServices.get().getTime() == 1 ){
                return new Date(timeNow.getTime()+((1000*60*30*24)*30));
            } else if (findServices.get().getTime() == 3) {
                return new Date(timeNow.getTime()+((1000*60*30*24)*30)*3);
            }else if (findServices.get().getTime() == 9){
                return new Date(timeNow.getTime()+((1000*60*30*24)*30)*9);
            }else if (findServices.get().getTime() == 12){
                return new Date(timeNow.getTime()+((1000*60*30*24)*30)*12);
            }else{
                return new Date(timeNow.getTime()+((1000*60*30*24)*30)*12);
            }
        }
        return null;
    }
}
