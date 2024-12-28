package com.example.movieba.controller.userpub;

import com.example.movieba.controller.BaseController;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.service.CompanyService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1")
public class CompController extends BaseController {

    @Autowired
    private final CompanyService companyService;

    @GetMapping("/info-new-com/{id}")
    ResponseEntity<BaseResponse> infoNewsCom(@PathVariable long id){
        return success(companyService.findCom(id));
    }

    @GetMapping("/all-coms")
    ResponseEntity<BaseResponse> getComs(){
        return success(companyService.getAllCompany());
    }

    @GetMapping("/infoCom-detail/{id}")
    ResponseEntity<BaseResponse> infoCompaniesDetail(@PathVariable long id){
        return success(companyService.getCompanyById(id));
    }

    @GetMapping("/infoCom/{id}")
    ResponseEntity<BaseResponse> infoCompanies(@PathVariable long id){
        return success(companyService.getComByIdNew(id));
    }




    @GetMapping("/all-news-by-com/{id}")
    ResponseEntity<BaseResponse> allNewsByCom(@PathVariable long id){
        return success(companyService.getAllNewsByCom(id));
    }
}
