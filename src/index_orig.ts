import { getAuthOpts} from './authentication'


export async function handler() {
   const options = await getAuthOpts();
   console.log(options);
   console.log(JSON.stringify(options));

  const response = {
    statusCode: 200,
    body: JSON.stringify('Hello from Lambda!'),
  };
  return response;
};

await handler();
