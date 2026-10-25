import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);
export const build = (dir: string) => execAsync(`cd ${dir} && make`);
