import {v4 as uuidv4} from 'uuid';

export class UUID {
  private uuid: string;
  constructor() {
    this.uuid = uuidv4();
    console.log('------------------UUID CREATED');
  }
  getUUId = () => {
    return this.uuid;
  }
}
const uuid = new UUID();

export default uuid;
