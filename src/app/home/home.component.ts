import {DidSiopService} from './../did-siop.service';
import {Component, OnInit} from '@angular/core';
import {Location} from '@angular/common';
import uuid from '../uuid';
import {url} from 'inspector';
import Cookies from 'universal-cookie';
import {Router} from '@angular/router';

const cookies = new Cookies();

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss']
})
export class HomeComponent implements OnInit {

  public did_user: string;
  public did_error: any;
  public responseJWT;

  constructor(public did_siop: DidSiopService, location: Location, private router: Router) {
    const session = cookies.get('session');
    console.log('SESSION GET', session)
    if (session) {
      if (session.session_id) {
        did_siop.processResponse(session.id_token, session.session_id).then(result => {
          if (result.payload) {
            this.did_user = result.payload.did;
          }
          if (result.error) {
            this.did_error = result;
            console.log(this.did_error);
          }
        })
          .catch(err => {
            console.log(err);
          });
        //  mobile
      } else {
        // extension 2nd time
        did_siop.processResponse(session.id_token).then(result => {
          if (result.payload) {
            this.did_user = result.payload.did;
          }
          if (result.error) {
            this.did_error = result;
            console.log(this.did_error);
          }
        })
          .catch(err => {
            console.log(err);
          });
      }

    } else {
      const response = location.path(true).split('#')[1];
      if (response) {
        this.responseJWT = response;
        did_siop.processResponse(response).then(result => {
          if (result.payload) {
            this.did_user = result.payload.did;
            const sessionExtension = {
              session_id: null,
              id_token: response
            };
            cookies.set('session', JSON.stringify(sessionExtension), {path: '/home'});
          }
          if (result.error) {
            this.did_error = result;
            console.log(this.did_error);
          }
        })
          .catch(err => {
            console.log(err);
          });

      } else {
        this.router.navigateByUrl(`/`);
      }
    }


  }

  ngOnInit(): void {
  }

  onLogout = () => {
    cookies.remove('session');
    this.did_siop.resetService();
    this.router.navigateByUrl(`/`);
  }
}
