import { Component, OnInit } from '@angular/core';
import { DidSiopService } from '../did-siop.service';
import { faChrome, faFirefox, faEdge, faGoogleDrive } from '@fortawesome/free-brands-svg-icons';
import uuid from "../uuid";
import { Router } from '@angular/router';

@Component({
  selector: 'app-index',
  templateUrl: './index.component.html',
  styleUrls: ['./index.component.scss', './index.component.responsive.scss']
})

export class IndexComponent implements OnInit {
  did_siop_request: string;
  storesData = {
    chrome: {
      link: 'https://chrome.google.com/webstore/detail/did-siop/ondpkioapbcbamnjdimjfhaelgojblad?hl=en-US&gclid=EAIaIQobChMI8MWH0Pq46gIVig4rCh3qDwHKEAAYASAAEgJiiPD_BwE',
      icon: faChrome
    },
    edge: {
      link: 'https://microsoftedge.microsoft.com/addons/detail/didsiop/obkplhmcoocpddcaompifaciljjnclfk?hl=en-GB',
      icon: faFirefox
    },
    fireFox: {
      link: 'https://addons.mozilla.org/en-US/firefox/addon/did-siop/',
      icon: faEdge
    },
    drive: {
      link: 'https://drive.google.com/drive/folders/1vTUBK9G9A5rmZ_-ZojALi_j0oXoIqjgQ?usp=sharing',
      icon: faGoogleDrive
    }
  };

  constructor(public did_siop: DidSiopService, private router: Router) {

    const server = 'https://e7452037d0af.ngrok.io/';
    did_siop.getRequest(uuid.getUUId()).then(res => {
      this.did_siop_request = res;
      console.log(res);
    });
    const source = new EventSource(`${server}subscribe?session_id=${uuid.getUUId()}`);
    source.addEventListener('message', message => {
      const data = JSON.parse(message.data);
      console.log(data);
      if (data.token) {
        this.router.navigateByUrl(`/home#${data.token}`);
      }
      // Display the event data in the `content` div
    });
  }

  ngOnInit(): void {
  }
}
